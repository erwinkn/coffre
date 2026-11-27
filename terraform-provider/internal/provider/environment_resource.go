package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

// listedKey is the private state's key for what the last refresh read of an environment beyond its
// attributes: whether this caller may take its protection off, `{"unprotectable": true}`.
const listedKey = "listed"

type environmentResource struct {
	data *configured
}

func newEnvironmentResource() resource.Resource { return &environmentResource{} }

var (
	_ resource.ResourceWithConfigure   = (*environmentResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*environmentResource)(nil)
	_ resource.ResourceWithImportState = (*environmentResource)(nil)
)

type environmentModel struct {
	ID        types.String `tfsdk:"id"`
	Project   types.String `tfsdk:"project"`
	Slug      types.String `tfsdk:"slug"`
	Parent    types.String `tfsdk:"parent"`
	Protected types.Bool   `tfsdk:"protected"`
}

func (m environmentModel) at() string { return m.Project.ValueString() + "/" + m.Slug.ValueString() }

func (r *environmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (r *environmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One of a project's environments: one that holds nothing yet, or a fork that inherits another. Destroyed, it is archived, with its keys: coffre deletes one for good only for an Admin or Owner of the instance.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "`project/slug`, which `terraform import` takes too."},
			"project": schema.StringAttribute{
				Required: true, Validators: []validator.String{slug{}},
				Description: "The project's slug. Fixed once made.",
			},
			"slug": schema.StringAttribute{
				Required: true, Validators: []validator.String{slug{}},
				Description: "The environment's slug. Fixed once made: rename it in coffre, then import it under the new slug.",
			},
			"parent": schema.StringAttribute{
				Optional: true, Validators: []validator.String{slug{}},
				Description: "The environment of the same project it inherits from: its keys are the parent's until it holds its own. Fixed once made. Making one takes `secret.read` on the parent.",
			},
			"protected": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Whether it is protected: in it, a role holds only its protected column. Only an Owner of the project, signed in as themselves (`session = true`), takes the protection off.",
			},
		},
	}
}

func (r *environmentResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if data := configuredOf(req); data != nil {
		r.data = data
	}
}

type environmentListed struct {
	Unprotectable bool `json:"unprotectable,omitempty"`
}

func (r *environmentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Project.IsUnknown() || plan.Slug.IsUnknown() {
		plan.ID = types.StringUnknown()
	} else {
		plan.ID = types.StringValue(plan.at())
	}
	defer func() { resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...) }()
	if req.State.Raw.IsNull() {
		return
	}
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, change := range map[string][2]types.String{"project": {state.Project, plan.Project}, "slug": {state.Slug, plan.Slug}, "parent": {state.Parent, plan.Parent}} {
		if change[1].IsUnknown() || change[0].Equal(change[1]) {
			continue
		}
		why := map[string]string{
			"project": "An environment stays in its project: make one in the other project, and remove this one from the configuration.",
			"slug":    "coffre keeps an archived environment's slug, so Terraform cannot archive it and make another. Rename it in coffre, then `terraform state rm` it and import it under the new slug, with the coffre_secret resources in it.",
			"parent":  "coffre has no call that changes what an environment inherits from. Make another environment, and move to it.",
		}[name]
		resp.Diagnostics.AddAttributeError(path.Root(name), state.at()+": its "+name+" is fixed once made", why)
	}
	if state.Protected.ValueBool() && !plan.Protected.IsUnknown() && !plan.Protected.ValueBool() {
		raw, diags := req.Private.GetKey(ctx, listedKey)
		resp.Diagnostics.Append(diags...)
		var listed environmentListed
		_ = json.Unmarshal(raw, &listed)
		switch {
		case r.data != nil && r.data.by != "session":
			resp.Diagnostics.AddAttributeError(path.Root("protected"), state.at()+" stays protected",
				"Only an Owner of the project, signed in as themselves, takes an environment's protection off, and this provider signs in as "+r.data.signedIn()+". Take it off in coffre, or set protected = true.")
		case r.data != nil && !listed.Unprotectable:
			resp.Diagnostics.AddAttributeError(path.Root("protected"), state.at()+" stays protected",
				"Only an Owner of the project takes an environment's protection off, and "+r.data.person+" is none there. Ask one, or set protected = true.")
		}
	}
}

func (r *environmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	project, slug := plan.Project.ValueString(), plan.Slug.ValueString()
	_, err := r.data.client.CreateEnvironment(ctx, project, slug, plan.Parent.ValueString())
	if coffre.Is(err, http.StatusConflict, "exists") {
		resp.Diagnostics.AddError(plan.at()+" is in coffre already",
			fmt.Sprintf("Terraform makes environments that are not there yet; an archived one keeps its slug. To manage this one, restore it in coffre if it is archived, then import it:\n\n  terraform import <address> %s", plan.at()))
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Could not make "+plan.at(), err.Error())
		return
	}
	plan.ID = types.StringValue(plan.at())
	if plan.Protected.ValueBool() {
		if err := r.data.client.EditEnvironment(ctx, project, slug, map[string]any{"protected": true}); err != nil {
			// Made, but not protected: the state says so, and the next plan protects it. Archiving it to try again would cost its slug.
			plan.Protected = types.BoolValue(false)
			resp.Diagnostics.AddWarning("Made "+plan.at()+", and could not protect it", err.Error()+"\n\nThe next plan protects it.")
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *environmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	project, err := r.data.client.Project(ctx, state.Project.ValueString(), false)
	if err != nil {
		resp.Diagnostics.AddError("Could not list the projects", err.Error())
		return
	}
	if project == nil {
		// A lost grant must not empty the state (section 3): who can see the project still keeps it.
		resp.Diagnostics.AddError("Cannot see the project "+state.Project.ValueString(),
			fmt.Sprintf("coffre lists no project %s to %s: it was deleted, or this sign-in holds nothing in it. The state is kept. If it is gone, remove its environments from the configuration, or `terraform state rm` them.", state.Project.ValueString(), r.whom()))
		return
	}
	listed := project.Environment(state.Slug.ValueString())
	if listed == nil || listed.Archived() {
		// Archived or gone: the next plan makes it again, which coffre refuses for an archived one, saying so.
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(state.at())
	state.Parent = types.StringPointerValue(listed.Parent)
	state.Protected = types.BoolValue(listed.Protected)
	raw, _ := json.Marshal(environmentListed{Unprotectable: listed.Unprotectable})
	resp.Diagnostics.Append(resp.Private.SetKey(ctx, listedKey, raw)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *environmentResource) whom() string {
	if r.data.person != "" {
		return r.data.person
	}
	return "this provider's sign-in"
}

func (r *environmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Protected.Equal(state.Protected) {
		if err := r.data.client.EditEnvironment(ctx, state.Project.ValueString(), state.Slug.ValueString(), map[string]any{"protected": plan.Protected.ValueBool()}); err != nil {
			resp.Diagnostics.AddError("Could not change "+state.at(), err.Error())
			return
		}
	}
	plan.ID = types.StringValue(plan.at())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *environmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.data.client.EditEnvironment(ctx, state.Project.ValueString(), state.Slug.ValueString(), map[string]any{"archived": true})
	switch {
	case err == nil, coffre.Is(err, http.StatusNotFound, ""), coffre.Is(err, http.StatusConflict, "archived"):
	case coffre.Is(err, http.StatusConflict, "inherited"), coffre.Is(err, http.StatusConflict, "referenced"):
		resp.Diagnostics.AddError("Could not archive "+state.at(), err.Error()+"\n\nNothing was archived.")
	default:
		resp.Diagnostics.AddError("Could not archive "+state.at(), err.Error())
	}
}

func (r *environmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	project, environment, ok := strings.Cut(req.ID, "/")
	if !ok || !slugPattern.MatchString(project) || !slugPattern.MatchString(environment) {
		resp.Diagnostics.AddError("Not an environment's ID", fmt.Sprintf("%q is not project/environment, such as billing/prod.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), project)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("slug"), environment)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
