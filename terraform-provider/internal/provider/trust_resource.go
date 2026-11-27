package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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

const trustType = "coffre_trust"

// The profiles a coffre_trust takes: the CI runs' (bearer, at /api/auth/oidc, or a workload's with a
// policy) and the workload platforms' whose binding is claims and a policy alone (@coffre/core's
// WORKLOAD_PROFILES, less enrollment and cloudflare).
var trustProfiles = []string{"github", "github-reusable", "github-reusable-organization", "gitlab", "custom", "kubernetes", "gcp", "azure", "fly", "vercel", "aws"}

// The issuer a profile means when none is given (@coffre/core's defaultIssuer); "" for one that names its own.
func defaultIssuer(profile string) string {
	switch {
	case strings.HasPrefix(profile, "github"):
		return "https://token.actions.githubusercontent.com"
	case profile == "gitlab":
		return "https://gitlab.com"
	case profile == "gcp":
		return "https://accounts.google.com"
	case profile == "aws":
		return "urn:coffre:aws"
	}
	return ""
}

// The claim that says what started a run, which a binding names one or several values of (@coffre/core's EVENT_CLAIM).
func eventClaim(profile string) string {
	switch {
	case strings.HasPrefix(profile, "github"):
		return "event_name"
	case profile == "gitlab":
		return "pipeline_source"
	}
	return ""
}

// The profiles a CI run's exchange takes, with no policy (@coffre/core's BEARER_PROFILES).
var bearerProfiles = []string{"github", "github-reusable", "github-reusable-organization", "gitlab", "custom"}

// The profiles whose binding's policy always says keyAudience (@coffre/core's KEY_NAMING_PROFILES).
var keyNaming = []string{"github", "github-reusable", "github-reusable-organization", "gcp", "fly", "vercel"}

type trustResource struct {
	data *configured
}

func newTrustResource() resource.Resource { return &trustResource{} }

var (
	_ resource.ResourceWithConfigure      = (*trustResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*trustResource)(nil)
	_ resource.ResourceWithValidateConfig = (*trustResource)(nil)
	_ resource.ResourceWithImportState    = (*trustResource)(nil)
)

type trustModel struct {
	ID            types.String `tfsdk:"id"`
	Service       types.String `tfsdk:"service"`
	Profile       types.String `tfsdk:"profile"`
	Issuer        types.String `tfsdk:"issuer"`
	Claims        types.Map    `tfsdk:"claims"`
	Events        types.Set    `tfsdk:"events"`
	ClaimPrefixes types.Map    `tfsdk:"claim_prefixes"`
	Scope         types.Map    `tfsdk:"scope"`
	Label         types.String `tfsdk:"label"`
	Policy        *policyModel `tfsdk:"policy"`
}

type policyModel struct {
	Audience        types.String `tfsdk:"audience"`
	KeyAudience     types.Bool   `tfsdk:"key_audience"`
	Sources         types.Set    `tfsdk:"sources"`
	SessionHours    types.Int64  `tfsdk:"session_hours"`
	UnsignedUploads types.Bool   `tfsdk:"unsigned_uploads"`
	Repeats         types.Bool   `tfsdk:"repeats"`
}

func (r *trustResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trust"
}

func (r *trustResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	text := func(description string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Validators: []validator.String{stringvalidator.LengthAtLeast(1)}, Description: description}
	}
	resp.Schema = schema.Schema{
		Description: "One of a service account's trust bindings: which CI runs, or which workloads, sign in as it, by the ID token their platform signs. Applied by a person (`session = true`). coffre never edits a binding: every change makes a new one in place of this one, in one change, so its id changes. Destroyed, it is removed, and what it issued ends.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The binding's id. `terraform import` takes `token:<name>/<id>`."},
			"service": schema.StringAttribute{
				Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:  []validator.String{member{servicesOnly: true}},
				Description: "The service account it signs in as, `token:<name>`: a coffre_service_account's `member`.",
			},
			"profile": schema.StringAttribute{
				Required: true, Validators: []validator.String{stringvalidator.OneOf(trustProfiles...)},
				Description: "Whose tokens it takes: `github`, `github-reusable`, `github-reusable-organization`, `gitlab` or `custom` (any other issuer), or a workload platform's: `kubernetes`, `gcp`, `azure`, `fly`, `vercel`, `aws`.",
			},
			"issuer": schema.StringAttribute{
				Optional: true, Computed: true, Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
				Description: "The issuer's URL. Left out, the profile's own: github.com's, gitlab.com's, Google's, or `urn:coffre:aws`; any other profile names its issuer.",
			},
			"claims": schema.MapAttribute{
				Required: true, ElementType: types.StringType,
				Validators:  []validator.Map{mapvalidator.NoNullValues(), mapvalidator.ValueStringsAre(stringvalidator.LengthAtLeast(1))},
				Description: "The claims a token must carry, each its exact value, such as `{ repository_id = \"41532\", ref = \"refs/heads/main\" }`. Each profile requires some: coffre says which.",
			},
			"events": schema.SetAttribute{
				Optional: true, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeAtLeast(1), setvalidator.NoNullValues()},
				Description: "What may start the run, one or several: GitHub's `event_name` (`push`, `workflow_dispatch`, …), GitLab's `pipeline_source`.",
			},
			"claim_prefixes": schema.MapAttribute{
				Optional: true, ElementType: types.StringType, Validators: []validator.Map{mapvalidator.NoNullValues()},
				Description: "A `custom` binding's claims matched by their start, whole segments each ended by `/`: `{ sub = \"org/1/project/2/\" }`, for an issuer whose `sub` names each run.",
			},
			"scope": schema.MapAttribute{
				Optional: true, Computed: true, ElementType: types.StringType,
				Validators: []validator.Map{mapvalidator.SizeAtLeast(1), mapvalidator.NoNullValues(), mapvalidator.KeysAre(placePath{}), mapvalidator.ValueStringsAre(stringvalidator.RegexMatches(rolePattern, "a role's id"))},
				Description: "What its credentials reach, by place and role, within what the account holds. coffre seals it on the binding when it makes it: left out, " +
					"what the account holds then, or, for a binding made in place of another, what that one reached and the account still holds, so a change never widens it. " +
					"A grant given to the account later is not in it: name the scope to reach it.",
			},
			"label": text("A label, shown beside it in coffre."),
			"policy": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Makes a `github`, `gitlab` or `custom` binding a workload's, for key-bound sessions at /api/auth/workload; left out, it is a CI run's, for the provider's and CLI's `oidc` sign-in. A workload platform's binding is always a workload's: left out, its policy is coffre's defaults. An instance that issues no bearer credential (`useOnly`) makes every binding a workload's.",
				Attributes: map[string]schema.Attribute{
					"audience":     text("An `azure` binding's audience, the exact one Entra puts in its tokens."),
					"key_audience": schema.BoolAttribute{Optional: true, Description: "The token's audience must name the session's key. Always so for GitHub, GCP, Fly and Vercel."},
					"sources": schema.SetAttribute{
						Optional: true, ElementType: types.StringType, Validators: []validator.Set{setvalidator.SizeBetween(1, 16), setvalidator.NoNullValues()},
						Description: "CIDRs a session's client address must be within, as coffre writes them: `162.220.232.0/24`.",
					},
					"session_hours": schema.Int64Attribute{
						Optional: true, Validators: []validator.Int64{int64validator.Between(1, 168)},
						Description: "A session's hard end after its proof, in hours: 24 unless set.",
					},
					"unsigned_uploads": schema.BoolAttribute{Optional: true, Description: "A streamed upload no digest binds may go through a credential that takes one."},
					"repeats":          schema.BoolAttribute{Optional: true, Description: "A `custom` issuer hands out the same token until it expires: none is spent, each lives an hour at most, and the session ends at its exp. Never beside key_audience."},
				},
			},
		},
	}
}

func (r *trustResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if data := configuredOf(req); data != nil {
		r.data = data
	}
}

func (r *trustResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config trustModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Profile.IsUnknown() || config.Profile.IsNull() {
		return
	}
	profile := config.Profile.ValueString()
	event := eventClaim(profile)
	if !config.Events.IsNull() && event == "" {
		resp.Diagnostics.AddAttributeError(path.Root("events"), "No event claim", fmt.Sprintf("A %s binding names no event: its claims say which runs it takes.", profile))
	}
	if event != "" && !config.Claims.IsUnknown() {
		if _, named := config.Claims.Elements()[event]; named {
			resp.Diagnostics.AddAttributeError(path.Root("claims"), event+" goes in events", fmt.Sprintf("Name what may start the run in events = [\"push\"]: a %s binding takes one or several there.", profile))
		}
	}
	if !config.ClaimPrefixes.IsNull() && profile != "custom" {
		resp.Diagnostics.AddAttributeError(path.Root("claim_prefixes"), "Only a custom binding matches a prefix", fmt.Sprintf("A %s binding pins IDs its platform never reuses: name each exactly in claims.", profile))
	}
	if config.Issuer.IsNull() && defaultIssuer(profile) == "" {
		resp.Diagnostics.AddAttributeError(path.Root("issuer"), "No issuer", fmt.Sprintf("A %s binding names its issuer's URL.", profile))
	}
	if !config.Claims.IsUnknown() && !config.ClaimPrefixes.IsUnknown() {
		for name := range config.ClaimPrefixes.Elements() {
			if _, both := config.Claims.Elements()[name]; both {
				resp.Diagnostics.AddAttributeError(path.Root("claim_prefixes").AtMapKey(name), name+" is in claims too",
					"A claim is matched exactly, in claims, or by its start, in claim_prefixes: name it in one.")
			}
		}
	}
	if p := config.Policy; p != nil {
		if slices.Contains(keyNaming, profile) && !p.KeyAudience.IsUnknown() && !p.KeyAudience.IsNull() && !p.KeyAudience.ValueBool() {
			resp.Diagnostics.AddAttributeError(path.Root("policy").AtName("key_audience"), "A "+profile+" token names the session's key",
				fmt.Sprintf("%s lets its caller choose a token's audience, so coffre requires it to name the session's key: a copied token then works for no other key. Leave key_audience out.", profile))
		}
		if !p.Sources.IsUnknown() && !p.Sources.IsNull() {
			for _, each := range p.Sources.Elements() {
				source, ok := each.(types.String)
				if !ok || source.IsUnknown() {
					continue
				}
				if _, ok := cidr(source.ValueString()); !ok {
					resp.Diagnostics.AddAttributeError(path.Root("policy").AtName("sources"), "Not a CIDR",
						fmt.Sprintf("%q is not a block such as 162.220.232.0/24 or 2001:db8::/32, with no bit set past its length.", source.ValueString()))
				}
			}
		}
	}
}

// cidr is a block as coffre writes it: RFC 5952's spelling, no bit set past its length.
func cidr(text string) (string, bool) {
	prefix, err := netip.ParsePrefix(text)
	if err != nil || prefix != prefix.Masked() {
		return "", false
	}
	return prefix.String(), true
}

// shape is a binding as coffre compares it: what makes it, in one spelling, so a refresh tells a
// binding changed in coffre from one written another way.
type shape struct {
	Profile, Issuer, Label string
	Claims, Prefixes       map[string]string
	Events                 []string
	Scope                  map[string]string
	Policy                 *policyShape
}

type policyShape struct {
	Audience                      string
	KeyAudience, Unsigned, Repeat bool
	Sources                       []string
	SessionHours                  int64
}

func (s *shape) normal() *shape {
	empty := func(m map[string]string) map[string]string {
		if len(m) == 0 {
			return nil
		}
		return m
	}
	s.Claims, s.Prefixes, s.Scope = empty(s.Claims), empty(s.Prefixes), empty(s.Scope)
	slices.Sort(s.Events)
	if len(s.Events) == 0 {
		s.Events = nil
	}
	if s.Policy == nil && !slices.Contains(bearerProfiles, s.Profile) {
		// A workload platform's binding is a workload's: one asked with no policy holds coffre's defaults.
		s.Policy = &policyShape{}
	}
	if s.Policy != nil {
		for i, source := range s.Policy.Sources {
			if canonical, ok := cidr(source); ok {
				s.Policy.Sources[i] = canonical
			}
		}
		slices.Sort(s.Policy.Sources)
		s.Policy.Sources = slices.Compact(s.Policy.Sources)
		if len(s.Policy.Sources) == 0 {
			s.Policy.Sources = nil
		}
		// What coffre sets itself, or holds when left out.
		if slices.Contains(keyNaming, s.Profile) {
			s.Policy.KeyAudience = true
		}
		if s.Policy.SessionHours == 24 {
			s.Policy.SessionHours = 0
		}
	}
	return s
}

func setStrings(ctx context.Context, set types.Set, diags *diag.Diagnostics) []string {
	var out []string
	if !set.IsNull() && !set.IsUnknown() {
		diags.Append(set.ElementsAs(ctx, &out, false)...)
	}
	return out
}

// known says whether a value is known through and through: a set or a map with one unknown element
// in it is known itself.
func known(ctx context.Context, values ...attr.Value) bool {
	for _, value := range values {
		raw, err := value.ToTerraformValue(ctx)
		if err != nil || !raw.IsFullyKnown() {
			return false
		}
	}
	return true
}

// shapeOf is the binding a model asks for; false while any of it is unknown but its scope, which
// wholly unknown is coffre's to seal, and asked for as none, or when it cannot be read, which it adds to diags.
func shapeOf(ctx context.Context, m trustModel, diags *diag.Diagnostics) (*shape, bool) {
	if !known(ctx, m.Profile, m.Issuer, m.Claims, m.Events, m.ClaimPrefixes, m.Label) || (!m.Scope.IsUnknown() && !known(ctx, m.Scope)) {
		return nil, false
	}
	var read diag.Diagnostics
	s := &shape{
		Profile: m.Profile.ValueString(), Issuer: m.Issuer.ValueString(), Label: m.Label.ValueString(),
		Claims: stringMap(ctx, m.Claims, &read), Prefixes: stringMap(ctx, m.ClaimPrefixes, &read),
		Events: setStrings(ctx, m.Events, &read), Scope: stringMap(ctx, m.Scope, &read),
	}
	if p := m.Policy; p != nil {
		if !known(ctx, p.Audience, p.KeyAudience, p.Sources, p.SessionHours, p.UnsignedUploads, p.Repeats) {
			return nil, false
		}
		s.Policy = &policyShape{Audience: p.Audience.ValueString(), KeyAudience: p.KeyAudience.ValueBool(), Sources: setStrings(ctx, p.Sources, &read),
			SessionHours: p.SessionHours.ValueInt64(), Unsigned: p.UnsignedUploads.ValueBool(), Repeat: p.Repeats.ValueBool()}
	}
	if read.HasError() {
		diags.Append(read...)
		return nil, false
	}
	return s.normal(), true
}

// listedShape is a binding as coffre lists it.
func listedShape(b coffre.Binding) *shape {
	s := &shape{Profile: b.Profile, Issuer: b.Issuer, Claims: map[string]string{}, Prefixes: map[string]string{}, Scope: b.Scope}
	if b.Label != nil {
		s.Label = *b.Label
	}
	event := eventClaim(b.Profile)
	for name, raw := range b.Claims {
		var one string
		var several []string
		var prefix struct {
			Prefix *string `json:"prefix"`
		}
		switch {
		case json.Unmarshal(raw, &one) == nil && name == event:
			s.Events = append(s.Events, one)
		case json.Unmarshal(raw, &one) == nil:
			s.Claims[name] = one
		case json.Unmarshal(raw, &several) == nil:
			s.Events = append(s.Events, several...)
		case json.Unmarshal(raw, &prefix) == nil && prefix.Prefix != nil:
			s.Prefixes[name] = *prefix.Prefix
		}
	}
	if b.Policy != nil {
		p := &policyShape{}
		read := func(name string, into any) { _ = json.Unmarshal(b.Policy[name], into) }
		read("audience", &p.Audience)
		read("keyAudience", &p.KeyAudience)
		read("sources", &p.Sources)
		read("sessionHours", &p.SessionHours)
		read("unsignedUploads", &p.Unsigned)
		read("repeats", &p.Repeat)
		s.Policy = p
	}
	return s.normal()
}

// unsaid names what of a listed binding coffre_trust cannot say, "" when nothing.
func unsaid(b coffre.Binding) string {
	switch {
	case !slices.Contains(trustProfiles, b.Profile):
		return "profile, " + b.Profile + ", is none coffre_trust takes"
	case len(b.Keys) > 0 && string(b.Keys) != "null":
		return "issuer's keys are uploaded to coffre"
	case b.Policy["reads"] != nil:
		return "policy names the reads it allows"
	}
	return ""
}

// model writes a listed binding's shape into the model, as a configuration would say it.
func (s *shape) model(m *trustModel) {
	optional := func(in map[string]string) types.Map {
		if len(in) == 0 {
			return types.MapNull(types.StringType)
		}
		return types.MapValueMust(types.StringType, stringValues(in))
	}
	set := func(in []string) types.Set {
		if len(in) == 0 {
			return types.SetNull(types.StringType)
		}
		values := make([]attrValue, len(in))
		for i, each := range in {
			values[i] = types.StringValue(each)
		}
		return types.SetValueMust(types.StringType, values)
	}
	m.Profile, m.Issuer = types.StringValue(s.Profile), types.StringValue(s.Issuer)
	m.Claims = types.MapValueMust(types.StringType, stringValues(s.Claims))
	m.Events, m.ClaimPrefixes, m.Scope = set(s.Events), optional(s.Prefixes), optional(s.Scope)
	m.Label = types.StringNull()
	if s.Label != "" {
		m.Label = types.StringValue(s.Label)
	}
	m.Policy = nil
	if p := s.Policy; p != nil {
		m.Policy = &policyModel{Audience: types.StringNull(), KeyAudience: types.BoolNull(), Sources: set(p.Sources), SessionHours: types.Int64Null(), UnsignedUploads: types.BoolNull(), Repeats: types.BoolNull()}
		if p.Audience != "" {
			m.Policy.Audience = types.StringValue(p.Audience)
		}
		if p.KeyAudience && !slices.Contains(keyNaming, s.Profile) {
			m.Policy.KeyAudience = types.BoolValue(true)
		}
		if p.SessionHours != 0 {
			m.Policy.SessionHours = types.Int64Value(p.SessionHours)
		}
		if p.Unsigned {
			m.Policy.UnsignedUploads = types.BoolValue(true)
		}
		if p.Repeat {
			m.Policy.Repeats = types.BoolValue(true)
		}
		// A workload platform's binding with coffre's defaults is written with no policy at all.
		q := m.Policy
		if !slices.Contains(bearerProfiles, s.Profile) && q.Audience.IsNull() && q.KeyAudience.IsNull() && q.Sources.IsNull() && q.SessionHours.IsNull() && q.UnsignedUploads.IsNull() && q.Repeats.IsNull() {
			m.Policy = nil
		}
	}
}

// binding is what POST /api/members/:member/bindings takes for a shape.
func (s *shape) binding(replaces ...string) coffre.NewBinding {
	claims := map[string]any{}
	for name, value := range s.Claims {
		claims[name] = value
	}
	if event := eventClaim(s.Profile); event != "" && len(s.Events) > 0 {
		if len(s.Events) == 1 {
			claims[event] = s.Events[0]
		} else {
			claims[event] = s.Events
		}
	}
	for name, prefix := range s.Prefixes {
		claims[name] = map[string]string{"prefix": prefix}
	}
	made := coffre.NewBinding{Profile: s.Profile, Claims: claims, Scope: s.Scope, Replaces: replaces}
	if s.Issuer != "" {
		made.Issuer = &s.Issuer
	}
	if s.Label != "" {
		made.Label = &s.Label
	}
	if p := s.Policy; p != nil {
		policy := map[string]any{}
		if p.Audience != "" {
			policy["audience"] = p.Audience
		}
		if p.KeyAudience {
			policy["keyAudience"] = true
		}
		if len(p.Sources) > 0 {
			policy["sources"] = p.Sources
		}
		if p.SessionHours != 0 {
			policy["sessionHours"] = p.SessionHours
		}
		if p.Unsigned {
			policy["unsignedUploads"] = true
		}
		if p.Repeat {
			policy["repeats"] = true
		}
		made.Policy = &policy
	}
	return made
}

func (r *trustResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if !personOnly(r.data, trustType, &resp.Diagnostics) || req.Plan.Raw.IsNull() {
		return
	}
	var plan, config trustModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.Issuer.IsNull() && !plan.Profile.IsUnknown() {
		plan.Issuer = types.StringValue(defaultIssuer(plan.Profile.ValueString()))
	}
	plan.ID = types.StringUnknown()
	sealed := config.Scope.IsNull()
	if sealed {
		plan.Scope = types.MapUnknown(types.StringType)
	}
	if !req.State.Raw.IsNull() {
		var state trustModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		kept := plan
		if sealed {
			kept.Scope = state.Scope
		}
		planned, ok := shapeOf(ctx, kept, &resp.Diagnostics)
		was, _ := shapeOf(ctx, state, &diag.Diagnostics{})
		// The same binding: it stays, with the scope coffre sealed on it. Any change makes a new one in
		// its place, whose id coffre draws, and whose scope, left out, coffre seals again.
		if ok && was != nil && reflect.DeepEqual(planned, was) && plan.Service.Equal(state.Service) {
			plan = kept
			plan.ID = state.ID
		}
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// bind makes the binding a plan asks for, in place of `replaces` if given.
func (r *trustResource) bind(ctx context.Context, plan *trustModel, diags *diag.Diagnostics, replaces ...string) bool {
	asked, ok := shapeOf(ctx, *plan, diags)
	service := plan.Service.ValueString()
	if !ok {
		diags.AddError("Could not bind "+service, "Some of the binding this plan asks for is unknown or unreadable. Nothing was changed.")
		return false
	}
	made, err := r.data.client.Bind(ctx, service, asked.binding(replaces...))
	switch {
	case coffre.Is(err, http.StatusNotFound, "unknown_principal"):
		diags.AddError("No service account "+service, "coffre has no such live service account: set it up first, with a coffre_service_account. ("+err.Error()+")")
		return false
	case err != nil && len(replaces) > 0 && (coffre.Is(err, http.StatusNotFound, "") || coffre.Is(err, http.StatusConflict, "stale")):
		diags.AddError(service+"'s binding changed after this plan was made", "It was removed or replaced in coffre since the plan saw it. Nothing was changed: plan again. ("+err.Error()+")")
		return false
	case err != nil:
		diags.AddError("Could not bind "+service, err.Error())
		return false
	}
	plan.ID, plan.Scope = types.StringValue(made.ID), types.MapValueMust(types.StringType, stringValues(made.Scope))
	return true
}

func (r *trustResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !personOnly(r.data, trustType, &resp.Diagnostics) {
		return
	}
	var plan trustModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !r.bind(ctx, &plan, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *trustResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !personOnly(r.data, trustType, &resp.Diagnostics) {
		return
	}
	var plan, state trustModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.ID.IsUnknown() {
		// Nothing of what makes it changed.
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	if !r.bind(ctx, &plan, &resp.Diagnostics, state.ID.ValueString()) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *trustResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !personOnly(r.data, trustType, &resp.Diagnostics) {
		return
	}
	var state trustModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	service := state.Service.ValueString()
	bindings, live, err := r.data.client.Bindings(ctx, service)
	switch {
	case coffre.Is(err, http.StatusForbidden, ""):
		resp.Diagnostics.AddError("Cannot see "+service+"'s trust bindings",
			fmt.Sprintf("coffre lists a service account's bindings to the account itself, whoever runs the instance, and a person who manages it, and %s does not manage %s. The state is kept: refresh as one of them. (%s)", r.data.whom(), service, err))
		return
	case err != nil:
		resp.Diagnostics.AddError("Could not list "+service+"'s trust bindings", err.Error())
		return
	case !live:
		resp.State.RemoveResource(ctx)
		return
	}
	index := slices.IndexFunc(bindings, func(b coffre.Binding) bool { return b.ID == state.ID.ValueString() })
	if index < 0 {
		// Removed or replaced in coffre: the next plan makes it again.
		resp.State.RemoveResource(ctx)
		return
	}
	// coffre never edits a binding, so the one by this id is the one the state made: the listing fills
	// in only an imported one, and the state keeps the configuration's spelling.
	if state.Profile.IsNull() {
		// Imported: a profile is required, so only an import leaves it null. A binding this resource
		// cannot say whole is refused, since the next change would make it again without what it left out.
		listed := bindings[index]
		if why := unsaid(listed); why != "" {
			resp.Diagnostics.AddError("Cannot import "+state.Service.ValueString()+"'s binding "+listed.ID,
				"Its "+why+", which coffre_trust does not manage: a change to it would make it again without. Keep it out of Terraform, or remake it as coffre_trust says it.")
			return
		}
		listedShape(listed).model(&state)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *trustResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !personOnly(r.data, trustType, &resp.Diagnostics) {
		return
	}
	var state trustModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.data.client.Unbind(ctx, state.Service.ValueString(), state.ID.ValueString())
	if err != nil && !coffre.Is(err, http.StatusNotFound, "") {
		resp.Diagnostics.AddError("Could not remove "+state.Service.ValueString()+"'s binding "+state.ID.ValueString(), err.Error())
	}
}

func (r *trustResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !personOnly(r.data, trustType, &resp.Diagnostics) {
		return
	}
	at := strings.LastIndex(req.ID, "/")
	if at < 0 || memberProblem(req.ID[:at], true) != "" || req.ID[at+1:] == "" {
		resp.Diagnostics.AddError("Not a trust binding's ID", fmt.Sprintf("%q is not token:<name>/<binding id>, with the id coffre lists it by.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service"), req.ID[:at])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID[at+1:])...)
	// Read fills the rest from the listing; claims must be a map, not null, for it to.
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("claims"), map[string]string{})...)
}
