package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

type grantResource struct {
	data *configured
}

func newGrantResource() resource.Resource { return &grantResource{} }

var (
	_ resource.ResourceWithConfigure   = (*grantResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*grantResource)(nil)
	_ resource.ResourceWithImportState = (*grantResource)(nil)
)

type grantModel struct {
	ID          types.String `tfsdk:"id"`
	Member      types.String `tfsdk:"member"`
	Project     types.String `tfsdk:"project"`
	Environment types.String `tfsdk:"environment"`
	Role        types.String `tfsdk:"role"`
	Until       types.String `tfsdk:"until"`
}

// place is the grant's place by path: `billing` or `billing/prod`.
func (m grantModel) place() string {
	if m.Environment.IsNull() || m.Environment.ValueString() == "" {
		return m.Project.ValueString()
	}
	return m.Project.ValueString() + "/" + m.Environment.ValueString()
}

func (m grantModel) at() string { return m.place() + "/" + m.Member.ValueString() }

func (r *grantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant"
}

func (r *grantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "One member's role at one place: coffre keeps one grant per member per place, so this is that grant, and every other is left alone. Written only over the grant its plan saw. Destroyed, it is revoked.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "`billing/prod/token:deploy`: the place, then the member. `terraform import` takes it too."},
			"member": schema.StringAttribute{
				Required: true, PlanModifiers: replace, Validators: []validator.String{member{}},
				Description: "Who holds it: `user:<email>`, in lowercase as coffre keeps it, or `token:<name>`. A member already: a person once let in, a service account once set up.",
			},
			"project": schema.StringAttribute{
				Required: true, PlanModifiers: replace, Validators: []validator.String{slug{}},
				Description: "The project's slug.",
			},
			"environment": schema.StringAttribute{
				Optional: true, PlanModifiers: replace, Validators: []validator.String{slug{}},
				Description: "One of its environments. Left out, the grant is on the whole project.",
			},
			"role": schema.StringAttribute{
				Required:    true,
				Validators:  []validator.String{stringvalidator.RegexMatches(rolePattern, "a role's id, such as viewer")},
				Description: "The role's id: one coffre ships, such as `viewer` or `developer`, or a custom one.",
			},
			"until": schema.StringAttribute{
				Computed:    true,
				Description: "An end someone set outside Terraform, as coffre lists it. A grant Terraform owns has none: the plan makes it standing again.",
			},
		},
	}
}

func (r *grantResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if data := configuredOf(req); data != nil {
		r.data = data
	}
}

func (r *grantResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Member.IsUnknown() || plan.Project.IsUnknown() || plan.Environment.IsUnknown() {
		plan.ID = types.StringUnknown()
	} else {
		plan.ID = types.StringValue(plan.at())
	}
	// No end, whatever was found: the apply makes the grant standing.
	plan.Until = types.StringNull()
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// set writes one place of a member's grants, over what `was` says it holds there.
func (r *grantResource) set(ctx context.Context, m grantModel, was *coffre.Held, diags *diag.Diagnostics) bool {
	err := r.data.client.SetAccess(ctx, m.Member.ValueString(), map[string]coffre.Wanted{m.place(): {Role: m.Role.ValueString(), Was: was}})
	switch {
	case err == nil:
		return true
	case coffre.Is(err, http.StatusConflict, "stale") && was == nil:
		diags.AddError(m.Member.ValueString()+" holds a grant at "+m.place()+" already",
			fmt.Sprintf("Terraform makes grants where the member holds none, so that one made by hand is not taken over unseen. To manage it, import it:\n\n  terraform import <address> %s\n\nNothing was changed.", m.at()))
	case coffre.Is(err, http.StatusConflict, "stale"):
		diags.AddError(m.at()+" changed after this plan was made",
			"Someone changed or revoked the grant since the plan saw it. Nothing was changed: plan again.")
	default:
		diags.AddError("Could not grant "+m.Role.ValueString()+" at "+m.place()+" to "+m.Member.ValueString(), err.Error())
	}
	return false
}

func (r *grantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !r.set(ctx, plan, nil, &resp.Diagnostics) {
		return
	}
	plan.ID, plan.Until = types.StringValue(plan.at()), types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *grantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// What the plan's refresh saw there: the change lands over that grant only.
	was := &coffre.Held{Role: state.Role.ValueString(), Until: state.Until.ValueStringPointer()}
	if !r.set(ctx, plan, was, &resp.Diagnostics) {
		return
	}
	plan.ID, plan.Until = types.StringValue(plan.at()), types.StringNull()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *grantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	who := state.Member.ValueString()
	access, err := r.data.client.Access(ctx, who)
	switch {
	case coffre.Is(err, http.StatusForbidden, ""):
		resp.Diagnostics.AddError("Cannot see "+who+"'s grants",
			fmt.Sprintf("coffre shows a member's grants to whoever manages access somewhere, or manages the service account, and %s does neither: %s\n\nThe state is kept: refresh as someone who does.", r.data.whom(), err))
		return
	case err != nil:
		resp.Diagnostics.AddError("Could not read "+who+"'s grants", err.Error())
		return
	case access == nil || access.Status != "active":
		// No such member, or removed: the grant is gone, and the next plan makes it again, which coffre refuses, saying why.
		resp.State.RemoveResource(ctx)
		return
	}
	held := access.At(state.place())
	if held == nil {
		// coffre shows the grants at the places the caller manages access in: absent elsewhere is unseen, not revoked.
		if !access.SeesAll() {
			project, err := r.data.client.Project(ctx, state.Project.ValueString(), false)
			if err != nil {
				resp.Diagnostics.AddError("Could not list the projects", err.Error())
				return
			}
			if project == nil || !project.May("grant.manage") {
				resp.Diagnostics.AddError("Cannot see the grants at "+state.place(),
					fmt.Sprintf("coffre shows %s only the grants at places where it manages access (grant.manage), and %s is not one. The state is kept: refresh as someone who manages access there.", r.data.whom(), state.Project.ValueString()))
				return
			}
		}
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(state.at())
	state.Role = types.StringValue(held.Role)
	state.Until = types.StringPointerValue(held.ExpiresAt)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *grantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Revoking is not guarded: it is the direction that is always safe.
	err := r.data.client.SetAccess(ctx, state.Member.ValueString(), map[string]coffre.Wanted{state.place(): {}})
	if err != nil && !coffre.Is(err, http.StatusNotFound, "not_a_member") && !coffre.Is(err, http.StatusConflict, "removed") {
		resp.Diagnostics.AddError("Could not revoke "+state.at(), err.Error())
	}
}

// ImportState takes `billing/prod/token:deploy`: the place, then the member, from the first segment
// with a `:`, which no slug has.
func (r *grantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	split := -1
	for i, part := range parts {
		if strings.Contains(part, ":") {
			split = i
			break
		}
	}
	bad := func() {
		resp.Diagnostics.AddError("Not a grant's ID", fmt.Sprintf("%q is not <project>[/<environment>]/<member>, such as billing/prod/token:deploy or billing/user:bo@acme.example.", req.ID))
	}
	if split < 1 || split > 2 || !validPlace(strings.Join(parts[:split], "/")) {
		bad()
		return
	}
	who := strings.Join(parts[split:], "/")
	if why := memberProblem(who, false); why != "" {
		bad()
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), parts[0])...)
	if split == 2 {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("environment"), parts[1])...)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("member"), who)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
