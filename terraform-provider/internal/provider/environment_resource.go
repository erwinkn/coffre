package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
				Optional: true, Computed: true,
				Description: "Whether it is protected: in it, a person holds only their role's protected column; a service account holds its role as anywhere. Left out, as coffre makes it: a fork of a protected environment is protected, any other not. Only an Owner of the project, signed in as themselves (`session = true`), takes the protection off.",
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

// fixed says why each attribute an environment keeps once made cannot change.
var fixed = map[string]string{
	"project": "An environment stays in its project: make one in the other project, and remove this one from the configuration.",
	"slug":    "coffre keeps an archived environment's slug, so Terraform cannot archive it and make another. Rename it in coffre, then `terraform state rm` it and import it under the new slug, with the coffre_secret resources in it.",
	"parent":  "coffre has no call that changes what an environment inherits from. Make another environment, and move to it.",
}

// moved names each fixed attribute the plan changes; one unknown changes, as far as anyone can tell.
func moved(state, plan environmentModel) []string {
	changes := map[string][2]types.String{"project": {state.Project, plan.Project}, "slug": {state.Slug, plan.Slug}, "parent": {state.Parent, plan.Parent}}
	var names []string
	for _, name := range sortedKeys(changes) {
		if !changes[name][0].Equal(changes[name][1]) {
			names = append(names, name)
		}
	}
	return names
}

func (r *environmentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan, config environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
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
		r.planMade(ctx, &plan, config, &resp.Diagnostics)
		return
	}
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, name := range moved(state, plan) {
		resp.Diagnostics.AddAttributeError(path.Root(name), state.at()+": its "+name+" is fixed once made", fixed[name])
	}
	if config.Protected.IsNull() {
		// Left out: as coffre has it.
		plan.Protected = state.Protected
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
				"Only an Owner of the project takes an environment's protection off, and "+r.data.whom()+" is none there. Ask one, or set protected = true.")
		}
	}
}

// planMade plans a new environment's protection: coffre protects a fork of a protected one itself.
func (r *environmentResource) planMade(ctx context.Context, plan *environmentModel, config environmentModel, diags *diag.Diagnostics) {
	inherits := !plan.Parent.IsNull()
	parentProtected, known := false, !inherits
	if inherits && !plan.Parent.IsUnknown() && !plan.Project.IsUnknown() && r.data != nil {
		// A parent not listed yet is made in the same apply: its protection is the apply's to tell.
		if project, err := r.data.client.Project(ctx, plan.Project.ValueString(), false); err == nil && project != nil {
			if parent := project.Environment(plan.Parent.ValueString()); parent != nil {
				parentProtected, known = parent.Protected, true
			}
		}
	}
	switch {
	case config.Protected.IsNull() && known && (parentProtected || !inherits):
		plan.Protected = types.BoolValue(parentProtected)
	case config.Protected.IsNull():
		// A parent unprotected now may be protected before this one is made, in this apply or beside it.
		plan.Protected = types.BoolUnknown()
	case parentProtected && !plan.Protected.IsUnknown() && !plan.Protected.ValueBool():
		diags.AddAttributeError(path.Root("protected"), plan.at()+" would be protected",
			fmt.Sprintf("coffre protects a fork of a protected environment, and %s/%s is. Set protected = true, or leave it out.", plan.Project.ValueString(), plan.Parent.ValueString()))
	}
}

func (r *environmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	project, slug := plan.Project.ValueString(), plan.Slug.ValueString()
	made, err := r.data.client.CreateEnvironment(ctx, project, slug, plan.Parent.ValueString())
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
	// Made, whatever comes next: the state says so. Terraform marks one saved with an error tainted, and replacing it
	// would archive it, whose slug coffre keeps: untaint it instead.
	const untaint = "\n\nIt is made, and in the state. Do not let Terraform replace it, which would archive it and keep its slug: run\n\n  terraform untaint <address>\n\nthen plan again."
	asked := plan.Protected
	plan.Protected = types.BoolValue(made.Protected)
	switch {
	case !asked.IsUnknown() && asked.ValueBool() && !made.Protected:
		if err := r.data.client.EditEnvironment(ctx, project, slug, map[string]any{"protected": true}); err != nil {
			resp.Diagnostics.AddError("Made "+plan.at()+", and could not protect it", err.Error()+untaint)
		} else {
			plan.Protected = types.BoolValue(true)
		}
	case !asked.IsUnknown() && !asked.ValueBool() && made.Protected:
		resp.Diagnostics.AddError(plan.at()+" is protected",
			fmt.Sprintf("coffre protects a fork of a protected environment, and %s/%s was by the time it was made. Set protected = true.", project, plan.Parent.ValueString())+untaint)
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
			fmt.Sprintf("coffre lists no project %s to %s: it was deleted, or this sign-in holds nothing in it. The state is kept. If it is gone, remove its environments from the configuration, or `terraform state rm` them.", state.Project.ValueString(), r.data.whom()))
		return
	}
	listed := project.Environment(state.Slug.ValueString())
	if listed != nil && listed.Details == nil {
		resp.Diagnostics.AddError("Cannot see "+state.at(),
			fmt.Sprintf("coffre lists %s to %s by name alone, which does not say whether it is archived. The state is kept: refresh as someone who manages environments in %s, or holds a grant in it.", state.at(), r.data.whom(), state.Project.ValueString()))
		return
	}
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

func (r *environmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The plan refuses these: one unknown then is known now.
	if names := moved(state, plan); len(names) > 0 {
		for _, name := range names {
			resp.Diagnostics.AddAttributeError(path.Root(name), state.at()+": its "+name+" is fixed once made", fixed[name]+" Nothing was changed.")
		}
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
	case err == nil:
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
