package provider

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

const serviceAccountType = "coffre_service_account"

type serviceAccountResource struct {
	data *configured
}

func newServiceAccountResource() resource.Resource { return &serviceAccountResource{} }

var (
	_ resource.ResourceWithConfigure   = (*serviceAccountResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*serviceAccountResource)(nil)
	_ resource.ResourceWithImportState = (*serviceAccountResource)(nil)
)

type serviceAccountModel struct {
	ID     types.String `tfsdk:"id"`
	Name   types.String `tfsdk:"name"`
	Member types.String `tfsdk:"member"`
	Grants types.Map    `tfsdk:"grants"`
	Ends   types.Map    `tfsdk:"ends"`
}

func (m serviceAccountModel) member() string { return "token:" + m.Name.ValueString() }

func (r *serviceAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *serviceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A service account, and every grant it holds. Applied by a person (`session = true`): coffre lets no service account set one up. Terraform never makes or keeps one of its tokens: CI signs in as it through a `coffre_trust`. Destroyed, it is removed: its grants revoked, its tokens, trust bindings and sessions ended.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "`token:<name>`, which `terraform import` takes too."},
			"name": schema.StringAttribute{
				Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:  []validator.String{stringvalidator.RegexMatches(serviceName, "a name with no space, not starting with :")},
				Description: "Its name, such as `deploy`: the account is `token:deploy`. coffre has no rename, so a change replaces it.",
			},
			"member": schema.StringAttribute{Computed: true, Description: "`token:<name>`, as grants and trust bindings name it."},
			"grants": schema.MapAttribute{
				Required: true, ElementType: types.StringType,
				Validators: []validator.Map{
					mapvalidator.SizeAtLeast(1),
					mapvalidator.KeysAre(placePath{}),
					mapvalidator.ValueStringsAre(stringvalidator.RegexMatches(rolePattern, "a role's id, such as viewer")),
				},
				Description: "Every grant it holds, by place: `{ \"billing\" = \"maintainer\", \"web/prod\" = \"viewer\" }`. A grant made outside Terraform is drift, and revoked. At least one: coffre admits a service account with its grants.",
			},
			"ends": schema.MapAttribute{
				Computed: true, ElementType: types.StringType,
				Description: "The grants found with an end someone set outside Terraform, by place, as coffre lists it. Always planned empty: the apply makes them standing.",
			},
		},
	}
}

func (r *serviceAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if data := configuredOf(req); data != nil {
		r.data = data
	}
}

func (r *serviceAccountResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if !personOnly(r.data, serviceAccountType, &resp.Diagnostics) || req.Plan.Raw.IsNull() {
		return
	}
	var plan serviceAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Name.IsUnknown() {
		plan.ID, plan.Member = types.StringUnknown(), types.StringUnknown()
	} else {
		plan.ID, plan.Member = types.StringValue(plan.member()), types.StringValue(plan.member())
	}
	plan.Ends = types.MapValueMust(types.StringType, map[string]attrValue{})
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// read is the account's grants, and their ends, by place; nil when it is gone. A caller that does not
// see all of them fails, rather than plan to undo what it cannot see.
func (r *serviceAccountResource) read(ctx context.Context, member string) (grants, ends map[string]string, found bool, err error) {
	access, err := r.data.client.Access(ctx, member)
	switch {
	case coffre.Is(err, http.StatusForbidden, ""):
		return nil, nil, false, fmt.Errorf("%s does not manage %s: coffre shows a service account's grants to whoever runs the instance, and to a person who could give it every grant it holds (or who admitted it, while it holds nothing). The state is kept: refresh as one of them. (%w)", r.data.whom(), member, err)
	case err != nil:
		return nil, nil, false, err
	case access == nil || access.Status != "active":
		return nil, nil, false, nil
	case !access.SeesAll():
		return nil, nil, false, fmt.Errorf("%s does not manage %s, so coffre shows it only the grants at places where it manages access, and the plan would undo the others. The state is kept: refresh as whoever runs the instance, or a person who could give it every grant it holds", r.data.whom(), member)
	}
	grants, ends = map[string]string{}, map[string]string{}
	for _, grant := range access.Grants {
		grants[grant.Place()] = grant.Role
		if grant.ExpiresAt != nil {
			ends[grant.Place()] = *grant.ExpiresAt
		}
	}
	return grants, ends, true, nil
}

func (r *serviceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !personOnly(r.data, serviceAccountType, &resp.Diagnostics) {
		return
	}
	var plan serviceAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	member := plan.member()
	there := func() {
		resp.Diagnostics.AddError(member+" is in coffre already",
			fmt.Sprintf("Terraform makes service accounts that are not there yet. To manage this one, import it:\n\n  terraform import <address> %s", member))
	}
	// coffre hides a member from whoever manages access nowhere (403): admitting then says what it is.
	access, err := r.data.client.Access(ctx, member)
	switch {
	case err != nil && !coffre.Is(err, http.StatusForbidden, ""):
		resp.Diagnostics.AddError("Could not read "+member, err.Error()+"\n\nNothing was changed.")
		return
	case access != nil && access.Status == "active":
		there()
		return
	}
	removed := access != nil && access.Status == "removed"
	wanted := map[string]coffre.Wanted{}
	for at, role := range stringMap(ctx, plan.Grants, &resp.Diagnostics) {
		wanted[at] = coffre.Wanted{Role: role}
	}
	created, err := r.data.client.AdmitService(ctx, member, wanted)
	switch {
	case removed && coffre.Is(err, http.StatusForbidden, "no_access"):
		resp.Diagnostics.AddError(member+" was removed", "coffre brings a removed service account back only for the person who removed it, or whoever runs the instance. Ask one of them, or give this resource another name. Nothing was changed. ("+err.Error()+")")
		return
	case coffre.Is(err, http.StatusConflict, "stale"):
		resp.Diagnostics.AddError(member+" holds grants already", "It was set up while this apply ran. Import it. Nothing was changed.")
		return
	case err != nil:
		resp.Diagnostics.AddError("Could not set up "+member, err.Error())
		return
	case !created:
		// Set up by someone else between the read and the admission: coffre gave the grants asked to the account it had.
		resp.Diagnostics.AddError(member+" was set up while this apply ran",
			fmt.Sprintf("coffre added the grants asked, at %s, to the ones it held. Import it, then plan: the plan shows what Terraform would change.\n\n  terraform import <address> %s", strings.Join(sortedKeys(wanted), ", "), member))
		return
	}
	plan.ID, plan.Member = types.StringValue(member), types.StringValue(member)
	plan.Ends = types.MapValueMust(types.StringType, map[string]attrValue{})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !personOnly(r.data, serviceAccountType, &resp.Diagnostics) {
		return
	}
	var state serviceAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	grants, ends, found, err := r.read(ctx, state.member())
	if err != nil {
		resp.Diagnostics.AddError("Could not read "+state.member(), err.Error())
		return
	}
	if !found {
		// Removed, or never there: the next plan sets it up again, which coffre refuses but to its remover.
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID, state.Member = types.StringValue(state.member()), types.StringValue(state.member())
	state.Grants = types.MapValueMust(types.StringType, stringValues(grants))
	state.Ends = types.MapValueMust(types.StringType, stringValues(ends))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !personOnly(r.data, serviceAccountType, &resp.Diagnostics) {
		return
	}
	var plan, state serviceAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	member := state.member()
	before, after := stringMap(ctx, state.Grants, &resp.Diagnostics), stringMap(ctx, plan.Grants, &resp.Diagnostics)
	ends := stringMap(ctx, state.Ends, &resp.Diagnostics)
	wanted := map[string]coffre.Wanted{}
	for at, role := range after {
		held, had := before[at]
		end, ended := ends[at]
		switch {
		case !had:
			wanted[at] = coffre.Wanted{Role: role}
		case held != role || ended:
			// Over what the plan's refresh saw there, end and all.
			was := &coffre.Held{Role: held}
			if ended {
				was.Until = &end
			}
			wanted[at] = coffre.Wanted{Role: role, Was: was}
		}
	}
	for at := range before {
		if _, kept := after[at]; !kept {
			wanted[at] = coffre.Wanted{}
		}
	}
	if len(wanted) > 0 {
		err := r.data.client.SetAccess(ctx, member, wanted)
		switch {
		case coffre.Is(err, http.StatusConflict, "stale"):
			resp.Diagnostics.AddError(member+" changed after this plan was made",
				"Someone changed its grants since the plan saw them. Nothing was changed: plan again.")
			return
		case err != nil:
			resp.Diagnostics.AddError("Could not change "+member+"'s grants at "+strings.Join(sortedKeys(wanted), ", "), err.Error())
			return
		}
	}
	plan.ID, plan.Member = types.StringValue(member), types.StringValue(member)
	plan.Ends = types.MapValueMust(types.StringType, map[string]attrValue{})
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !personOnly(r.data, serviceAccountType, &resp.Diagnostics) {
		return
	}
	var state serviceAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.client.RemoveMember(ctx, state.member()); err != nil {
		resp.Diagnostics.AddError("Could not remove "+state.member(), err.Error())
	}
}

func (r *serviceAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !personOnly(r.data, serviceAccountType, &resp.Diagnostics) {
		return
	}
	name, ok := strings.CutPrefix(req.ID, "token:")
	if !ok || !serviceName.MatchString(name) {
		resp.Diagnostics.AddError("Not a service account's ID", fmt.Sprintf("%q is not token:<name>, such as token:deploy.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), "token:"+name)...)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
