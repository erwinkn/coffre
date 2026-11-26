package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf16"

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
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

// A key as coffre names one (@coffre/core's secretKey).
var keyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// The longest value coffre takes, in UTF-16 code units, as its route counts them.
const valueLength = 64 * 1024

// writtenKey is the private state's key for what the provider wrote last: the version it
// was answered with and the key's row, `{"version": 7, "secret": "<uuid>"}`, and, once a
// refresh found the key reading anything else, `"drift": true`.
const writtenKey = "written"

type written struct {
	Version int64  `json:"version"`
	Secret  string `json:"secret,omitempty"`
	Drift   bool   `json:"drift,omitempty"`
}

type secretResource struct {
	client *coffre.Client
}

func newSecretResource() resource.Resource { return &secretResource{} }

var (
	_ resource.ResourceWithConfigure   = (*secretResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*secretResource)(nil)
	_ resource.ResourceWithImportState = (*secretResource)(nil)
)

type secretModel struct {
	ID             types.String `tfsdk:"id"`
	Project        types.String `tfsdk:"project"`
	Environment    types.String `tfsdk:"environment"`
	Key            types.String `tfsdk:"key"`
	ValueWO        types.String `tfsdk:"value_wo"`
	ValueWOVersion types.Int64  `tfsdk:"value_wo_version"`
	Sensitivity    types.String `tfsdk:"sensitivity"`
	Version        types.Int64  `tfsdk:"version"`
	VersionID      types.String `tfsdk:"version_id"`
	UpdatedBy      types.String `tfsdk:"updated_by"`
}

func (m secretModel) at() string {
	return m.Project.ValueString() + "/" + m.Environment.ValueString() + "/" + m.Key.ValueString()
}

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "One key of a coffre environment, and its value, which Terraform sends and keeps nowhere. Destroyed, the key is archived: coffre keeps its history.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "`project/environment/key`, which `terraform import` takes too.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"project": schema.StringAttribute{
				Required: true, PlanModifiers: replace, Validators: []validator.String{slug{}},
				Description: "The project's slug.",
			},
			"environment": schema.StringAttribute{
				Required: true, PlanModifiers: replace, Validators: []validator.String{slug{}},
				Description: "The environment's slug.",
			},
			"key": schema.StringAttribute{
				Required: true, PlanModifiers: replace,
				Validators:  []validator.String{stringvalidator.RegexMatches(keyPattern, "a key is a letter or _, then up to 127 letters, digits or _")},
				Description: "The key's name, such as `STRIPE_KEY`.",
			},
			"value_wo": schema.StringAttribute{
				Required: true, Sensitive: true, WriteOnly: true, Validators: []validator.String{value{}},
				Description: "The value: write-only, so kept in neither state nor plan. At most 64 KiB of text, with no NUL. Written when the key is made, and again each time value_wo_version changes.",
			},
			"value_wo_version": schema.Int64Attribute{
				Required:    true,
				Description: "Change it to write value_wo again: Terraform cannot tell a write-only value changed. A number you choose, never one made from the value.",
			},
			"sensitivity": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("secret"),
				Validators:  []validator.String{stringvalidator.OneOf("plain", "secret", "sensitive")},
				Description: "Who sees the value: `plain`, whoever lists the environment; `secret`, whoever reads it (the default); `sensitive`, nobody: it is only used. A change writes the value again, as a new version.",
			},
			"version": schema.Int64Attribute{
				Computed:    true,
				Description: "The version the key reads now, by number, as the last refresh or write saw it.",
			},
			"version_id": schema.StringAttribute{
				Computed:    true,
				Description: "That version's id: what the next write says it replaces, so that it never overwrites a version its plan did not see.",
			},
			"updated_by": schema.StringAttribute{
				Computed:    true,
				Description: "Who wrote that version.",
			},
		},
	}
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if data, ok := req.ProviderData.(*configured); ok {
		r.client = data.client
	}
}

// privateState is what Get and Set need of the framework's private state, whichever request carries it.
type privateState interface {
	GetKey(context.Context, string) ([]byte, diag.Diagnostics)
}

func writtenOf(ctx context.Context, private privateState) (*written, diag.Diagnostics) {
	raw, diags := private.GetKey(ctx, writtenKey)
	if diags.HasError() || len(raw) == 0 {
		return nil, diags
	}
	var got written
	if json.Unmarshal(raw, &got) != nil || got.Version < 1 {
		return nil, diags
	}
	return &got, diags
}

type privateSetter interface {
	SetKey(context.Context, string, []byte) diag.Diagnostics
}

func setWritten(ctx context.Context, private privateSetter, w *written) diag.Diagnostics {
	if w == nil {
		return private.SetKey(ctx, writtenKey, nil)
	}
	raw, _ := json.Marshal(w)
	return private.SetKey(ctx, writtenKey, raw)
}

// ours says whether the key reads, now, the version the provider wrote: its own live value, of the same
// row, at the same number. Anything else (written again, marked, made a reference, reset to a parent's,
// renamed away and another renamed onto its name) is someone else's.
func ours(w *written, listed *coffre.Listed) bool {
	return w != nil && listed != nil && listed.Own() && listed.Version != nil && *listed.Version == w.Version &&
		listed.Secret != nil && (w.Secret == "" || *listed.Secret == w.Secret)
}

// show puts what the listing says of the key into the model: its version, by number and id, its author and its sensitivity.
func show(m *secretModel, listed *coffre.Listed) {
	m.ID = types.StringValue(m.at())
	m.Version = types.Int64PointerValue(listed.Version)
	m.VersionID = types.StringPointerValue(listed.VersionID)
	m.UpdatedBy = types.StringPointerValue(listed.UpdatedBy)
	if listed.Sensitivity != nil {
		m.Sensitivity = types.StringValue(*listed.Sensitivity)
	}
}

func (r *secretResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Project.IsUnknown() && !plan.Environment.IsUnknown() && !plan.Key.IsUnknown() {
		plan.ID = types.StringValue(plan.at())
	}
	if req.State.Raw.IsNull() {
		resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
		return
	}
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	w, diags := writtenOf(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	asked := !plan.ValueWOVersion.Equal(state.ValueWOVersion) || !plan.Sensitivity.Equal(state.Sensitivity)
	// Imported, Terraform wrote nothing yet; or what the key reads is not what it wrote.
	drifted := w == nil || w.Drift
	if !asked && !drifted {
		plan.Version, plan.VersionID, plan.UpdatedBy = state.Version, state.VersionID, state.UpdatedBy
	} else {
		plan.Version, plan.VersionID, plan.UpdatedBy = types.Int64Unknown(), types.StringUnknown(), types.StringUnknown()
	}
	if drifted && w != nil {
		by := state.UpdatedBy.ValueString()
		if by == "" {
			by = "someone this account cannot see"
		}
		now := "a value Terraform did not write"
		if !state.Version.IsNull() {
			now = fmt.Sprintf("version %d, written by %s", state.Version.ValueInt64(), by)
		}
		resp.Diagnostics.AddWarning(state.at()+" was written outside Terraform",
			fmt.Sprintf("It reads %s; Terraform wrote version %d. Applying writes the configured value over it.", now, w.Version))
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	var configured types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_wo"), &configured)...)
	if resp.Diagnostics.HasError() {
		return
	}
	project, environment, key := plan.Project.ValueString(), plan.Environment.ValueString(), plan.Key.ValueString()
	sensitivity := plan.Sensitivity.ValueString()
	made, err := r.client.Write(ctx, project, environment, key, configured.ValueString(), sensitivity, coffre.Nothing)
	if coffre.Is(err, http.StatusConflict, "stale") {
		// It reads something now. In a fork, a value a parent passes down, which this environment's own overrides.
		listed, listErr := r.client.Key(ctx, project, environment, key, true)
		switch {
		case listErr != nil:
			err = listErr
		case listed != nil && listed.Inherited() && listed.Reference == nil && listed.VersionID != nil:
			made, err = r.client.Write(ctx, project, environment, key, configured.ValueString(), sensitivity, coffre.Version(*listed.VersionID))
		case listed != nil && listed.Inherited():
			resp.Diagnostics.AddError(plan.at()+" is inherited, and its version cannot be seen",
				fmt.Sprintf("It reads what %s passes down, as a reference or from an environment this account cannot list, so a write cannot say what it replaces. Nothing was written.", listed.Parent.From))
			return
		default:
			resp.Diagnostics.AddError(plan.at()+" is in coffre already",
				fmt.Sprintf("Terraform makes keys that hold nothing yet. To manage this one, import it:\n\n  terraform import <address> %s\n\nNothing was written.", plan.at()))
			return
		}
	}
	if coffre.Is(err, http.StatusConflict, "archived") {
		resp.Diagnostics.AddError(plan.at()+" is archived",
			"coffre keeps an archived key, with its history, under its name. Bring it back in coffre, then import it, or give this resource another key. Nothing was written.")
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Could not write "+plan.at(), err.Error())
		return
	}
	r.settle(ctx, &plan, made, &resp.State, resp.Private, &resp.Diagnostics)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	var configured types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("value_wo"), &configured)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// What the plan's refresh saw the key read: the write lands over that version only.
	if state.VersionID.IsNull() || state.VersionID.ValueString() == "" {
		resp.Diagnostics.AddError(state.at()+" reads no version Terraform can replace",
			"When this plan was made, the key was a reference, or inherited from an environment this account cannot list, so a write cannot say what it replaces. Make it a value in coffre, or remove it from Terraform. Nothing was written.")
		return
	}
	made, err := r.client.Write(ctx, plan.Project.ValueString(), plan.Environment.ValueString(), plan.Key.ValueString(),
		configured.ValueString(), plan.Sensitivity.ValueString(), coffre.Version(state.VersionID.ValueString()))
	switch {
	case coffre.Is(err, http.StatusConflict, "stale"):
		resp.Diagnostics.AddError(state.at()+" changed after this plan was made",
			"Someone wrote, archived, renamed or reset it since the plan saw it. Nothing was written: plan again.")
		return
	case coffre.Is(err, http.StatusConflict, "archived"):
		resp.Diagnostics.AddError(state.at()+" is archived", "It was archived since this plan was made. Nothing was written.")
		return
	case err != nil:
		resp.Diagnostics.AddError("Could not write "+state.at(), err.Error())
		return
	}
	r.settle(ctx, &plan, made, &resp.State, resp.Private, &resp.Diagnostics)
}

// stateSetter is what settle needs of a response's state.
type stateSetter interface {
	Set(context.Context, any) diag.Diagnostics
}

// settle records a write: the version it made, as private state, and what the key reads now, listed
// again for its id. Someone who wrote in between shows up as the version the key reads, and as drift.
// Only computed attributes come from the listing: the configured ones are what was written, so that
// the state is the plan's, whatever happened since.
func (r *secretResource) settle(ctx context.Context, m *secretModel, made coffre.Written, state stateSetter, private privateSetter, diags *diag.Diagnostics) {
	w := &written{Version: made.Version}
	m.ID = types.StringValue(m.at())
	m.Version, m.VersionID, m.UpdatedBy = types.Int64Value(made.Version), types.StringValue(""), types.StringValue("")
	listed, err := r.client.Key(ctx, m.Project.ValueString(), m.Environment.ValueString(), m.Key.ValueString(), true)
	switch {
	case err != nil:
		diags.AddWarning("Wrote "+m.at()+", and could not list it after", err.Error()+"\n\nThe next refresh lists it again.")
	case listed == nil || listed.Empty():
		// Gone or emptied since: the next refresh finds it so.
		w.Drift = true
	default:
		if listed.Own() && listed.Secret != nil {
			w.Secret = *listed.Secret
		}
		w.Drift = !ours(w, listed)
		m.Version = types.Int64PointerValue(listed.Version)
		m.VersionID = types.StringValue(valueOr(listed.VersionID))
		m.UpdatedBy = types.StringValue(valueOr(listed.UpdatedBy))
	}
	m.ValueWO = types.StringNull()
	tflog.Debug(ctx, "wrote a coffre key", map[string]any{"at": m.at(), "version": made.Version})
	diags.Append(setWritten(ctx, private, w)...)
	diags.Append(state.Set(ctx, m)...)
}

func valueOr(text *string) string {
	if text == nil {
		return ""
	}
	return *text
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	w, diags := writtenOf(ctx, req.Private)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	listed, err := r.client.Key(ctx, state.Project.ValueString(), state.Environment.ValueString(), state.Key.ValueString(), false)
	if err != nil {
		resp.Diagnostics.AddError("Could not list "+state.Project.ValueString()+"/"+state.Environment.ValueString(), err.Error())
		return
	}
	// Gone, or holding nothing: it is no more, and the next plan makes it again.
	if listed == nil || listed.Empty() {
		resp.State.RemoveResource(ctx)
		return
	}
	if w != nil {
		w.Drift = w.Drift || !ours(w, listed)
		if !w.Drift && w.Secret == "" {
			w.Secret = *listed.Secret
		}
	}
	show(&state, listed)
	resp.Diagnostics.Append(setWritten(ctx, resp.Private, w)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Archive(ctx, state.Project.ValueString(), state.Environment.ValueString(), state.Key.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not archive "+state.at(), err.Error())
	}
}

func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !keyPattern.MatchString(parts[2]) {
		resp.Diagnostics.AddError("Not a key's ID", fmt.Sprintf("%q is not project/environment/KEY, such as billing/prod/STRIPE_KEY.", req.ID))
		return
	}
	for name, at := range map[string]string{"project": parts[0], "environment": parts[1], "key": parts[2]} {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(name), at)...)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// slug holds a project or environment to one path segment, and no personal config (`dev@me`): a service account has none.
type slug struct{}

func (slug) Description(context.Context) string               { return "a slug: no / and no @" }
func (s slug) MarkdownDescription(ctx context.Context) string { return s.Description(ctx) }
func (slug) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	at := req.ConfigValue.ValueString()
	switch {
	case at == "" || strings.Contains(at, "/"):
		resp.Diagnostics.AddAttributeError(req.Path, "Not a slug", fmt.Sprintf("%q is not one slug, such as prod.", at))
	case strings.Contains(at, "@"):
		resp.Diagnostics.AddAttributeError(req.Path, "A personal config", fmt.Sprintf("%q names someone's personal config, which is theirs: a service account has none.", at))
	}
}

// value holds a value to what coffre takes, and says nothing of it in its errors: not even its length.
type value struct{}

func (value) Description(context.Context) string               { return "at most 64 KiB of text, with no NUL" }
func (v value) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (value) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	text := req.ConfigValue.ValueString()
	if strings.ContainsRune(text, 0) || len(utf16.Encode([]rune(text))) > valueLength {
		resp.Diagnostics.AddAttributeError(req.Path, "Not a value coffre takes", "A value is at most 64 KiB of text (65,536 UTF-16 code units), with no NUL.")
	}
}
