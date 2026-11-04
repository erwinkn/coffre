package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

// privateKey names the resource's private state (`kept`).
const privateKey = "coffre"

var (
	_ resource.ResourceWithConfigure   = (*secretResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*secretResource)(nil)
	_ resource.ResourceWithImportState = (*secretResource)(nil)
)

func newSecretResource() resource.Resource { return &secretResource{} }

type secretResource struct {
	client *coffre.Client
}

type secretModel struct {
	ID             types.String `tfsdk:"id"`
	Project        types.String `tfsdk:"project"`
	Environment    types.String `tfsdk:"environment"`
	Key            types.String `tfsdk:"key"`
	Sensitivity    types.String `tfsdk:"sensitivity"`
	ValueWO        types.String `tfsdk:"value_wo"`
	ValueWOVersion types.String `tfsdk:"value_wo_version"`
	OnDestroy      types.String `tfsdk:"on_destroy"`
	Version        types.Int64  `tfsdk:"version"`
	VersionID      types.String `tfsdk:"version_id"`
}

func (m *secretModel) id() string {
	return m.Project.ValueString() + "/" + m.Environment.ValueString() + "/" + m.Key.ValueString()
}

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "A key in coffre whose value Terraform writes and never reads back. Destroying it keeps the key unless on_destroy is \"archive\".",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "project/environment/key, which terraform import takes too.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project":     schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "The project's name."},
			"environment": schema.StringAttribute{Required: true, PlanModifiers: replace, Description: "The environment's name, a fork's included."},
			"key": schema.StringAttribute{
				Required: true, PlanModifiers: replace, Description: "The key's name.",
				Validators: []validator.String{stringvalidator.RegexMatches(keyName, "a key name is a letter or _, then letters, digits or _, 128 at most")},
			},
			"sensitivity": schema.StringAttribute{
				Required:    true,
				Description: "plain, secret or sensitive: who may see the value in coffre. Stricter marks the current value; looser needs value_wo_version changed in the same apply.",
				Validators:  []validator.String{stringvalidator.OneOf("plain", "secret", "sensitive")},
			},
			"value_wo": schema.StringAttribute{
				Required: true, WriteOnly: true, Sensitive: true,
				Description: "The value. Write-only: never in state or plan, sent on create and when value_wo_version changes, at no other time.",
			},
			"value_wo_version": schema.StringAttribute{
				Required:    true,
				Description: "Any string; when it changes, the next apply writes value_wo as a new version.",
			},
			"on_destroy": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("keep"),
				Description: "keep (the default: Terraform stops managing the key, which stays) or archive (the credential needs secret.archive).",
				Validators:  []validator.String{stringvalidator.OneOf("keep", "archive")},
			},
			"version":    schema.Int64Attribute{Computed: true, Description: "The key's current version number in coffre, as the last refresh or write saw it."},
			"version_id": schema.StringAttribute{Computed: true, Description: "That version's id, which an update sends as replaces."},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if client, ok := req.ProviderData.(*coffre.Client); ok {
		r.client = client
	}
}

// clientOf is the configured client, or an error saying the provider's
// configuration is not known yet.
func (r *secretResource) clientOf(diags *diag.Diagnostics) *coffre.Client {
	if r.client == nil {
		diags.AddError("coffre: provider not configured", "the provider's url or credential is not known yet; it must be known before coffre_secret can be read or written")
	}
	return r.client
}

func readKept(ctx context.Context, get func(context.Context, string) ([]byte, diag.Diagnostics), diags *diag.Diagnostics) kept {
	raw, d := get(ctx, privateKey)
	diags.Append(d...)
	var k kept
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &k); err != nil {
			diags.AddError("coffre: private state", "the resource's private state does not read: "+err.Error())
		}
	}
	return k
}

func writeKept(ctx context.Context, set func(context.Context, string, []byte) diag.Diagnostics, k kept, diags *diag.Diagnostics) {
	raw, err := json.Marshal(k)
	if err != nil {
		diags.AddError("coffre: private state", err.Error())
		return
	}
	diags.Append(set(ctx, privateKey, raw)...)
}

// failure says what a call's error means for this key.
func failure(id string, err error) string {
	switch {
	case coffre.IsStatus(err, http.StatusConflict, "stale"):
		return fmt.Sprintf("%s was written after this plan; plan again", id)
	case coffre.IsStatus(err, http.StatusForbidden, ""):
		return fmt.Sprintf("%s: the credential may not do this here: %s", id, err)
	}
	return fmt.Sprintf("%s: %s", id, err)
}

func (r *secretResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // a destroy: Delete says what it keeps
	}
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	known := !plan.Project.IsUnknown() && !plan.Environment.IsUnknown() && !plan.Key.IsUnknown()
	if known {
		plan.ID = types.StringValue(plan.id())
	}
	var state secretModel
	if !req.State.Raw.IsNull() {
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if req.State.Raw.IsNull() || moved(state, plan) {
		// A create, or a replacement's (a new address, which the attributes' RequiresReplace replaces): the key must be
		// absent, or in a fork inherited, at plan and again at apply. The old key's rules do not apply to the new one.
		plan.Version, plan.VersionID = types.Int64Unknown(), types.StringUnknown()
		if known && r.client != nil {
			listing, err := r.client.List(ctx, plan.Project.ValueString(), plan.Environment.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("coffre: create", failure(plan.id(), err))
				return
			}
			if _, problem := creatable(plan.id(), listing.Find(plan.Key.ValueString())); problem != "" {
				resp.Diagnostics.AddError("coffre: create", problem)
				return
			}
		}
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}
	private := readKept(ctx, req.Private.GetKey, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	decided := planUpdate(state.id(), optional(state.ValueWOVersion), optional(plan.ValueWOVersion),
		state.Sensitivity.ValueString(), plan.Sensitivity.ValueString(), !plan.Sensitivity.IsUnknown(), private.Parent)
	if decided.Error != "" {
		resp.Diagnostics.AddAttributeError(path.Root("sensitivity"), "coffre: sensitivity", decided.Error)
		return
	}
	if decided.Kind == nothing {
		plan.Version, plan.VersionID = state.Version, state.VersionID
	} else {
		plan.Version, plan.VersionID = types.Int64Unknown(), types.StringUnknown()
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// moved reports whether the plan names another key than the state: an
// address attribute changed, or is unknown, so the resource is replaced.
func moved(state, plan secretModel) bool {
	for _, pair := range [][2]types.String{{state.Project, plan.Project}, {state.Environment, plan.Environment}, {state.Key, plan.Key}} {
		if pair[1].IsUnknown() || pair[0].ValueString() != pair[1].ValueString() {
			return true
		}
	}
	return false
}

// optional is a known string's value, or nil while null or unknown.
func optional(value types.String) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	s := value.ValueString()
	return &s
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	client := r.clientOf(&resp.Diagnostics)
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var value types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_wo"), &value)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if value.IsNull() || value.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("value_wo"), "coffre: value_wo", "value_wo must be known at apply")
		return
	}
	id := plan.id()
	listing, err := client.List(ctx, plan.Project.ValueString(), plan.Environment.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("coffre: create", failure(id, err))
		return
	}
	existing := listing.Find(plan.Key.ValueString())
	replaces, problem := creatable(id, existing)
	if problem != "" {
		resp.Diagnostics.AddError("coffre: create", problem)
		return
	}
	v := value.ValueString()
	outcome, err := client.Set(ctx, plan.Project.ValueString(), plan.Environment.ValueString(), plan.Key.ValueString(),
		coffre.Write{Value: &v, Sensitivity: plan.Sensitivity.ValueString(), Replaces: replaces})
	if err != nil {
		resp.Diagnostics.AddError("coffre: create", failure(id, err))
		return
	}
	private := kept{Written: outcome.VersionID}
	if existing != nil && existing.Parent != nil {
		private.Parent = "overridden"
	}
	r.settle(ctx, &plan, outcome)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	writeKept(ctx, resp.Private.SetKey, private, &resp.Diagnostics)
}

// settle puts what a write made into the model, which keeps no value.
func (r *secretResource) settle(_ context.Context, model *secretModel, outcome *coffre.Outcome) {
	model.ID = types.StringValue(model.id())
	model.ValueWO = types.StringNull()
	model.Version = types.Int64Value(outcome.Version)
	model.VersionID = types.StringValue(outcome.VersionID)
	model.Sensitivity = types.StringValue(outcome.Sensitivity)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	private := readKept(ctx, req.Private.GetKey, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	client := r.clientOf(&resp.Diagnostics)
	if client == nil {
		return
	}
	id := state.id()
	listing, err := client.List(ctx, state.Project.ValueString(), state.Environment.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("coffre: refresh", failure(id, err))
		return
	}
	seen := refresh(id, listing.Find(state.Key.ValueString()), private)
	switch {
	case seen.Remove:
		resp.State.RemoveResource(ctx)
		return
	case seen.Error != "":
		resp.Diagnostics.AddError("coffre: refresh", seen.Error)
		return
	case seen.Warning != "":
		resp.Diagnostics.AddWarning("coffre: "+id+" changed outside Terraform", seen.Warning)
	}
	state.ID = types.StringValue(id)
	state.ValueWO = types.StringNull()
	state.Version = types.Int64PointerValue(seen.Version)
	state.VersionID = types.StringPointerValue(seen.VersionID)
	if seen.Sensitivity != nil {
		state.Sensitivity = types.StringValue(*seen.Sensitivity)
	}
	if state.OnDestroy.IsNull() {
		state.OnDestroy = types.StringValue("keep")
	}
	private.Parent = seen.Parent
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	writeKept(ctx, resp.Private.SetKey, private, &resp.Diagnostics)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	private := readKept(ctx, req.Private.GetKey, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id := plan.id()
	decided := applyUpdate(id, optional(state.ValueWOVersion), plan.ValueWOVersion.ValueString(), state.Sensitivity.ValueString(), plan.Sensitivity.ValueString(), private.Parent)
	if decided.Error != "" {
		resp.Diagnostics.AddAttributeError(path.Root("sensitivity"), "coffre: sensitivity", decided.Error)
		return
	}
	if decided.Kind == nothing {
		plan.ID, plan.ValueWO, plan.Version, plan.VersionID = types.StringValue(id), types.StringNull(), state.Version, state.VersionID
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	client := r.clientOf(&resp.Diagnostics)
	if client == nil {
		return
	}
	// The version the plan saw, from the prior state, never a fresh read: one written since makes this a 409 stale.
	written := coffre.Write{Sensitivity: plan.Sensitivity.ValueString(), Replaces: optional(state.VersionID)}
	if written.Replaces == nil {
		// The plan saw no version: an inherited key whose parent's versions the credential is not told. Nothing guards the
		// write, so the key must still be what the plan saw, as a create's is checked again at apply.
		listing, err := client.List(ctx, plan.Project.ValueString(), plan.Environment.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("coffre: update", failure(id, err))
			return
		}
		if problem := stillHidden(id, listing.Find(plan.Key.ValueString())); problem != "" {
			resp.Diagnostics.AddError("coffre: update", problem)
			return
		}
	}
	if decided.Kind == write {
		var value types.String
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_wo"), &value)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if value.IsNull() || value.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root("value_wo"), "coffre: value_wo", "value_wo must be known at apply")
			return
		}
		v := value.ValueString()
		written.Value = &v
	}
	outcome, err := client.Set(ctx, plan.Project.ValueString(), plan.Environment.ValueString(), plan.Key.ValueString(), written)
	if err != nil {
		resp.Diagnostics.AddError("coffre: update", failure(id, err))
		return
	}
	private.Written = outcome.VersionID
	if private.Parent == "inherited" {
		private.Parent = "overridden"
	}
	r.settle(ctx, &plan, outcome)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	writeKept(ctx, resp.Private.SetKey, private, &resp.Diagnostics)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.id()
	if state.OnDestroy.ValueString() != "archive" {
		resp.Diagnostics.AddWarning("coffre: "+id+" kept in coffre",
			fmt.Sprintf("on_destroy is \"keep\": Terraform no longer manages the key; its value and versions stay. Archive it in coffre (coffre archive %s) if it should go.", id))
		return
	}
	client := r.clientOf(&resp.Diagnostics)
	if client == nil {
		return
	}
	if err := client.Archive(ctx, state.Project.ValueString(), state.Environment.ValueString(), state.Key.ValueString()); err != nil {
		resp.Diagnostics.AddError("coffre: archive", failure(id, err))
	}
}

func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !keyName.MatchString(parts[2]) {
		resp.Diagnostics.AddError("coffre: import", fmt.Sprintf("import takes project/environment/key, as infra/prod/SCW_BACKUP_SECRET_KEY; got %q", req.ID))
		return
	}
	for name, value := range map[string]string{"id": req.ID, "project": parts[0], "environment": parts[1], "key": parts[2], "on_destroy": "keep"} {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(name), value)...)
	}
}
