package provider

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

func TestPersonOnly(t *testing.T) {
	for _, by := range []string{"token", "oidc"} {
		var diags diag.Diagnostics
		if personOnly(&configured{by: by}, "coffre_trust", &diags) || !diags.HasError() {
			t.Fatalf("%s: let through", by)
		}
		said := diags.Errors()[0]
		if said.Summary() != "coffre_trust is applied by a person" || !strings.Contains(said.Detail(), "("+by+")") || !strings.Contains(said.Detail(), "session = true") {
			t.Errorf("%s: %s: %s", by, said.Summary(), said.Detail())
		}
	}
	var diags diag.Diagnostics
	if !personOnly(&configured{by: "session"}, "coffre_trust", &diags) || diags.HasError() {
		t.Error("a person's session refused")
	}
	// Not configured yet (validation): nothing to say.
	if !personOnly(nil, "coffre_trust", &diags) || diags.HasError() {
		t.Error("an unconfigured provider refused")
	}
}

func TestMemberProblem(t *testing.T) {
	for named, ok := range map[string]bool{
		"user:bo@acme.example": true, "token:deploy": true, "token:a.b-c_d": true,
		"user:Bo@acme.example": false, "user:bo": false, "bo@acme.example": false, "token:": false, "token::x": false, "token:a b": false, "deploy": false,
	} {
		if got := memberProblem(named, false) == ""; got != ok {
			t.Errorf("%q: valid %v", named, got)
		}
	}
	if memberProblem("user:bo@acme.example", true) == "" {
		t.Error("a person taken for a service account")
	}
}

func TestValidPlace(t *testing.T) {
	for at, ok := range map[string]bool{"billing": true, "billing/prod": true, "billing/prod/x": false, "Billing": false, "billing/": false, "billing/dev@me": false, "": false} {
		if validPlace(at) != ok {
			t.Errorf("%q: valid %v", at, !ok)
		}
	}
}

func raw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(value)
	return out
}

func set(values ...string) types.Set {
	elements := make([]attr.Value, len(values))
	for i, value := range values {
		elements[i] = types.StringValue(value)
	}
	return types.SetValueMust(types.StringType, elements)
}

func strmap(values map[string]string) types.Map {
	return types.MapValueMust(types.StringType, stringValues(values))
}

// A binding as the configuration says it and as coffre lists it are the same shape, so a refresh plans nothing.
func TestBindingShapes(t *testing.T) {
	ctx := context.Background()
	github := trustModel{
		Service: types.StringValue("token:deploy"), Profile: types.StringValue("github"), Issuer: types.StringValue(defaultIssuer("github")),
		Claims: strmap(map[string]string{"repository_id": "41532", "ref": "refs/heads/main"}), Events: set("workflow_dispatch", "push"),
		ClaimPrefixes: types.MapNull(types.StringType), Scope: types.MapNull(types.StringType), Label: types.StringNull(),
		// What coffre sets of a GitHub workload's binding, and the default, left out or said.
		Policy: &policyModel{Audience: types.StringNull(), KeyAudience: types.BoolNull(), Sources: set("10.0.0.0/8"), SessionHours: types.Int64Value(24), UnsignedUploads: types.BoolValue(false), Repeats: types.BoolNull()},
	}
	listed := coffre.Binding{
		ID: "b1", Profile: "github", Issuer: "https://token.actions.githubusercontent.com",
		Claims: map[string]json.RawMessage{"event_name": raw(t, []string{"push", "workflow_dispatch"}), "ref": raw(t, "refs/heads/main"), "repository_id": raw(t, "41532")},
		Policy: map[string]json.RawMessage{"keyAudience": raw(t, true), "sources": raw(t, []string{"10.0.0.0/8"})},
	}
	asked, known := shapeOf(ctx, github, &diag.Diagnostics{})
	if !known || !reflect.DeepEqual(asked, listedShape(listed)) {
		t.Fatalf("configured %+v, listed %+v", asked, listedShape(listed))
	}
	// Sent, the events are the profile's event claim, several as a list.
	sent := asked.binding("old")
	if !reflect.DeepEqual(sent.Claims["event_name"], []string{"push", "workflow_dispatch"}) || sent.Policy == nil || (*sent.Policy)["sessionHours"] != nil || !reflect.DeepEqual(sent.Replaces, []string{"old"}) {
		t.Errorf("sent %+v", sent)
	}

	// A custom binding's prefix and repeats, #853's.
	capy := trustModel{
		Service: types.StringValue("token:capy"), Profile: types.StringValue("custom"), Issuer: types.StringValue("https://cloud.capy.example"),
		Claims: strmap(map[string]string{"project": "2"}), Events: types.SetNull(types.StringType), ClaimPrefixes: strmap(map[string]string{"sub": "org/1/project/2/"}),
		Scope: strmap(map[string]string{"billing/prod": "viewer"}), Label: types.StringValue("capy"),
		Policy: &policyModel{Audience: types.StringNull(), KeyAudience: types.BoolNull(), Sources: types.SetNull(types.StringType), SessionHours: types.Int64Null(), UnsignedUploads: types.BoolNull(), Repeats: types.BoolValue(true)},
	}
	listedCapy := coffre.Binding{
		ID: "b2", Profile: "custom", Issuer: "https://cloud.capy.example", Label: ptr("capy"), Scope: map[string]string{"billing/prod": "viewer"},
		Claims: map[string]json.RawMessage{"project": raw(t, "2"), "sub": raw(t, map[string]string{"prefix": "org/1/project/2/"})},
		Policy: map[string]json.RawMessage{"repeats": raw(t, true)},
	}
	asked, _ = shapeOf(ctx, capy, &diag.Diagnostics{})
	if !reflect.DeepEqual(asked, listedShape(listedCapy)) {
		t.Fatalf("configured %+v, listed %+v", asked, listedShape(listedCapy))
	}
	if sent := asked.binding(); !reflect.DeepEqual(sent.Claims["sub"], map[string]string{"prefix": "org/1/project/2/"}) || sent.Policy == nil || (*sent.Policy)["repeats"] != true {
		t.Errorf("sent %+v", sent)
	}

	// Changed in coffre: the listing differs, and the model takes what coffre holds.
	listedCapy.Policy = nil
	changed := listedShape(listedCapy)
	if reflect.DeepEqual(asked, changed) {
		t.Fatal("a bearer binding read as the workload's")
	}
	var model trustModel
	changed.model(&model)
	if model.Policy != nil || model.ClaimPrefixes.Elements()["sub"].(types.String).ValueString() != "org/1/project/2/" || model.Label.ValueString() != "capy" {
		t.Errorf("modelled %+v", model)
	}
	again, _ := shapeOf(ctx, model, &diag.Diagnostics{})
	if !reflect.DeepEqual(again, changed) {
		t.Errorf("modelled, then shaped: %+v, not %+v", again, changed)
	}
}

func TestDefaultIssuer(t *testing.T) {
	for profile, issuer := range map[string]string{"github": "https://token.actions.githubusercontent.com", "github-reusable": "https://token.actions.githubusercontent.com", "gitlab": "https://gitlab.com", "gcp": "https://accounts.google.com", "aws": "urn:coffre:aws", "custom": "", "kubernetes": ""} {
		if got := defaultIssuer(profile); got != issuer {
			t.Errorf("%s: %q", profile, got)
		}
	}
}

func unknownSet(values ...string) types.Set {
	elements := []attr.Value{types.StringUnknown()}
	for _, value := range values {
		elements = append(elements, types.StringValue(value))
	}
	return types.SetValueMust(types.StringType, elements)
}

// A collection known but for one element is not a known binding: it plans a new one, never "the same".
func TestBindingUnknowns(t *testing.T) {
	ctx := context.Background()
	base := func() trustModel {
		return trustModel{
			Service: types.StringValue("token:deploy"), Profile: types.StringValue("github"), Issuer: types.StringValue(defaultIssuer("github")),
			Claims: strmap(map[string]string{"repository_id": "41532"}), Events: types.SetNull(types.StringType),
			ClaimPrefixes: types.MapNull(types.StringType), Scope: types.MapNull(types.StringType), Label: types.StringNull(),
		}
	}
	if _, ok := shapeOf(ctx, base(), &diag.Diagnostics{}); !ok {
		t.Fatal("a known binding read as unknown")
	}
	m := base()
	m.Scope = types.MapUnknown(types.StringType)
	if _, ok := shapeOf(ctx, m, &diag.Diagnostics{}); !ok {
		t.Error("a scope coffre seals read as unknown")
	}
	for name, change := range map[string]func(*trustModel){
		"claims": func(m *trustModel) {
			m.Claims = types.MapValueMust(types.StringType, map[string]attr.Value{"repository_id": types.StringValue("41532"), "ref": types.StringUnknown()})
		},
		"events": func(m *trustModel) { m.Events = unknownSet("push") },
		"scope": func(m *trustModel) {
			m.Scope = types.MapValueMust(types.StringType, map[string]attr.Value{"billing": types.StringUnknown()})
		},
		"sources": func(m *trustModel) {
			m.Policy = &policyModel{Audience: types.StringNull(), KeyAudience: types.BoolNull(), Sources: unknownSet("10.0.0.0/8"), SessionHours: types.Int64Null(), UnsignedUploads: types.BoolNull(), Repeats: types.BoolNull()}
		},
	} {
		m := base()
		change(&m)
		if _, ok := shapeOf(ctx, m, &diag.Diagnostics{}); ok {
			t.Errorf("%s: an unknown element read as known", name)
		}
	}
}

// A null element is no binding's: reading it fails, saying so, rather than ask for less.
func TestBindingNulls(t *testing.T) {
	ctx := context.Background()
	m := trustModel{
		Service: types.StringValue("token:deploy"), Profile: types.StringValue("github"), Issuer: types.StringValue(defaultIssuer("github")),
		Claims:        types.MapValueMust(types.StringType, map[string]attr.Value{"repository_id": types.StringValue("41532"), "environment": types.StringNull()}),
		Events:        types.SetNull(types.StringType),
		ClaimPrefixes: types.MapNull(types.StringType), Scope: types.MapNull(types.StringType), Label: types.StringNull(),
	}
	var diags diag.Diagnostics
	if asked, ok := shapeOf(ctx, m, &diags); ok || asked != nil || !diags.HasError() {
		t.Errorf("a null claim read as %+v, %v, with %v", asked, ok, diags)
	}
}

// Imported, a workload platform's binding with coffre's default policy is written with none, as a
// configuration leaves it; a bearer profile's keeps `policy = {}`, which makes it a workload's.
func TestImportedPolicy(t *testing.T) {
	for profile, none := range map[string]bool{"kubernetes": true, "gcp": true, "custom": false, "github": false} {
		policy := map[string]json.RawMessage{}
		if profile == "gcp" {
			policy["keyAudience"] = raw(t, true)
		}
		var m trustModel
		listedShape(coffre.Binding{ID: "b", Profile: profile, Issuer: "https://issuer.acme.example", Claims: map[string]json.RawMessage{"sub": raw(t, "x")}, Policy: policy}).model(&m)
		if (m.Policy == nil) != none {
			t.Errorf("%s with coffre's default policy imports policy %+v", profile, m.Policy)
		}
	}
}

// What coffre fills in of a binding asked without it is the same binding: a workload platform's
// policy left out, GCP's key audience, a CIDR in another spelling.
func TestBindingDefaults(t *testing.T) {
	ctx := context.Background()
	model := func(profile string, policy *policyModel) trustModel {
		return trustModel{
			Service: types.StringValue("token:deploy"), Profile: types.StringValue(profile), Issuer: types.StringValue("https://issuer.acme.example"),
			Claims: strmap(map[string]string{"sub": "system:serviceaccount:web:api"}), Events: types.SetNull(types.StringType),
			ClaimPrefixes: types.MapNull(types.StringType), Scope: types.MapNull(types.StringType), Label: types.StringNull(), Policy: policy,
		}
	}
	listed := func(profile string, policy map[string]json.RawMessage) *shape {
		return listedShape(coffre.Binding{ID: "b", Profile: profile, Issuer: "https://issuer.acme.example", Claims: map[string]json.RawMessage{"sub": raw(t, "system:serviceaccount:web:api")}, Policy: policy})
	}
	for _, profile := range []string{"kubernetes", "gcp"} {
		asked, _ := shapeOf(ctx, model(profile, nil), &diag.Diagnostics{})
		policy := map[string]json.RawMessage{}
		if profile == "gcp" {
			policy["keyAudience"] = raw(t, true)
		}
		if got := listed(profile, policy); !reflect.DeepEqual(asked, got) {
			t.Errorf("%s with no policy: asked %+v, listed %+v", profile, asked.Policy, got.Policy)
		}
	}
	// A bearer profile's binding with no policy is a CI run's: not the workload's with coffre's defaults.
	asked, _ := shapeOf(ctx, model("custom", nil), &diag.Diagnostics{})
	if reflect.DeepEqual(asked, listed("custom", map[string]json.RawMessage{})) {
		t.Error("a CI run's binding read as a workload's")
	}
	spelled := &policyModel{Audience: types.StringNull(), KeyAudience: types.BoolNull(), Sources: set("2001:0DB8::/32", "10.0.0.0/8", "10.0.0.0/8"), SessionHours: types.Int64Null(), UnsignedUploads: types.BoolNull(), Repeats: types.BoolNull()}
	asked, _ = shapeOf(ctx, model("kubernetes", spelled), &diag.Diagnostics{})
	if got := listed("kubernetes", map[string]json.RawMessage{"sources": raw(t, []string{"10.0.0.0/8", "2001:db8::/32"})}); !reflect.DeepEqual(asked, got) {
		t.Errorf("sources: asked %v, listed %v", asked.Policy.Sources, got.Policy.Sources)
	}
	for text, ok := range map[string]bool{"10.0.0.0/8": true, "2001:DB8::/32": true, "10.0.0.1/8": false, "10.0.0.0": false, "010.0.0.0/8": false} {
		if _, got := cidr(text); got != ok {
			t.Errorf("cidr(%q): %v", text, got)
		}
	}
}

// trustConfig is a coffre_trust's configuration, every attribute not given null.
func trustConfig(t *testing.T, given map[string]tftypes.Value) tfsdk.Config {
	t.Helper()
	ctx := context.Background()
	var answer resource.SchemaResponse
	(&trustResource{}).Schema(ctx, resource.SchemaRequest{}, &answer)
	kind := answer.Schema.Type().TerraformType(ctx).(tftypes.Object)
	values := map[string]tftypes.Value{}
	for name, of := range kind.AttributeTypes {
		values[name] = tftypes.NewValue(of, nil)
		if value, ok := given[name]; ok {
			values[name] = value
		}
	}
	return tfsdk.Config{Schema: answer.Schema, Raw: tftypes.NewValue(kind, values)}
}

func TestTrustValidation(t *testing.T) {
	ctx := context.Background()
	text := func(value string) tftypes.Value { return tftypes.NewValue(tftypes.String, value) }
	texts := func(values map[string]string) tftypes.Value {
		out := map[string]tftypes.Value{}
		for name, value := range values {
			out[name] = text(value)
		}
		return tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, out)
	}
	var answer resource.SchemaResponse
	(&trustResource{}).Schema(ctx, resource.SchemaRequest{}, &answer)
	policyType := answer.Schema.Type().TerraformType(ctx).(tftypes.Object).AttributeTypes["policy"].(tftypes.Object)
	policy := func(given map[string]tftypes.Value) tftypes.Value {
		values := map[string]tftypes.Value{}
		for name, of := range policyType.AttributeTypes {
			values[name] = tftypes.NewValue(of, nil)
			if value, ok := given[name]; ok {
				values[name] = value
			}
		}
		return tftypes.NewValue(policyType, values)
	}
	for name, c := range map[string]struct {
		given  map[string]tftypes.Value
		refuse string
	}{
		"plain": {given: map[string]tftypes.Value{"profile": text("gcp"), "claims": texts(map[string]string{"sub": "1"})}},
		"key audience": {
			given:  map[string]tftypes.Value{"profile": text("gcp"), "claims": texts(map[string]string{"sub": "1"}), "policy": policy(map[string]tftypes.Value{"key_audience": tftypes.NewValue(tftypes.Bool, false)})},
			refuse: "A gcp token names the session's key",
		},
		"both": {
			given:  map[string]tftypes.Value{"profile": text("custom"), "issuer": text("https://cloud.capy.example"), "claims": texts(map[string]string{"sub": "x"}), "claim_prefixes": texts(map[string]string{"sub": "org/"})},
			refuse: "sub is in claims too",
		},
		"source": {
			given:  map[string]tftypes.Value{"profile": text("kubernetes"), "issuer": text("https://k8s.acme.example"), "claims": texts(map[string]string{"sub": "1"}), "policy": policy(map[string]tftypes.Value{"sources": tftypes.NewValue(tftypes.Set{ElementType: tftypes.String}, []tftypes.Value{text("10.0.0.1/8")})})},
			refuse: "Not a CIDR",
		},
	} {
		var resp resource.ValidateConfigResponse
		(&trustResource{}).ValidateConfig(ctx, resource.ValidateConfigRequest{Config: trustConfig(t, c.given)}, &resp)
		switch {
		case c.refuse == "" && resp.Diagnostics.HasError():
			t.Errorf("%s: refused %v", name, resp.Diagnostics)
		case c.refuse != "" && (len(resp.Diagnostics.Errors()) != 1 || resp.Diagnostics.Errors()[0].Summary() != c.refuse):
			t.Errorf("%s: said %v, not %q", name, resp.Diagnostics, c.refuse)
		}
	}
	// An empty issuer or label is no issuer or label: refused by the schema, rather than sent as none.
	for _, attribute := range []string{"issuer", "label"} {
		var resp validator.StringResponse
		for _, check := range answer.Schema.Attributes[attribute].(schema.StringAttribute).Validators {
			check.ValidateString(ctx, validator.StringRequest{Path: path.Root(attribute), ConfigValue: types.StringValue("")}, &resp)
		}
		if !resp.Diagnostics.HasError() {
			t.Errorf("%s = \"\" let through", attribute)
		}
	}
}

func TestServiceAccountImport(t *testing.T) {
	for _, id := range []string{"user:ada@acme.example", "deploy", "token:", "token::x"} {
		var resp resource.ImportStateResponse
		(&serviceAccountResource{}).ImportState(context.Background(), resource.ImportStateRequest{ID: id}, &resp)
		if !resp.Diagnostics.HasError() || resp.Diagnostics.Errors()[0].Summary() != "Not a service account's ID" {
			t.Errorf("%q imported: %v", id, resp.Diagnostics)
		}
	}
}

// A workload's binding at coffre's defaults is sent with its policy, {}: left out, coffre would make
// a CI run's bearer binding of it instead, and a CI run's binding is sent with none.
func TestBindingPolicySent(t *testing.T) {
	ctx := context.Background()
	none := func() *policyModel {
		return &policyModel{Audience: types.StringNull(), KeyAudience: types.BoolNull(), Sources: types.SetNull(types.StringType), SessionHours: types.Int64Null(), UnsignedUploads: types.BoolNull(), Repeats: types.BoolNull()}
	}
	defaults := none()
	defaults.SessionHours = types.Int64Value(24)
	notRepeating := none()
	notRepeating.Repeats = types.BoolValue(false)
	for _, profile := range []string{"custom", "gitlab"} {
		for name, policy := range map[string]*policyModel{"{}": none(), "session_hours = 24": defaults, "repeats = false": notRepeating, "none": nil} {
			m := trustModel{
				Service: types.StringValue("token:deploy"), Profile: types.StringValue(profile), Issuer: types.StringValue("https://issuer.acme.example"),
				Claims: strmap(map[string]string{"project": "2"}), Events: types.SetNull(types.StringType), ClaimPrefixes: types.MapNull(types.StringType),
				Scope: types.MapNull(types.StringType), Label: types.StringNull(), Policy: policy,
			}
			asked, ok := shapeOf(ctx, m, &diag.Diagnostics{})
			if !ok {
				t.Fatalf("%s with policy %s: unreadable", profile, name)
			}
			sent, err := json.Marshal(asked.binding())
			if err != nil {
				t.Fatal(err)
			}
			if has := strings.Contains(string(sent), `"policy":{}`); has != (policy != nil) {
				t.Errorf("%s with policy %s sent %s", profile, name, sent)
			}
			if policy == nil && strings.Contains(string(sent), `"policy"`) {
				t.Errorf("%s with no policy sent %s", profile, sent)
			}
		}
	}
}

// An import refuses a binding coffre_trust cannot say whole: the next change would make it again without.
func TestUnsaid(t *testing.T) {
	plain := coffre.Binding{ID: "b", Profile: "custom", Issuer: "https://issuer.acme.example", Keys: json.RawMessage("null"), Policy: map[string]json.RawMessage{}}
	if why := unsaid(plain); why != "" {
		t.Errorf("a plain binding is refused: %s", why)
	}
	keys, reads, enrolled := plain, plain, plain
	keys.Keys = json.RawMessage(`[{"kid":"k1"}]`)
	reads.Policy = map[string]json.RawMessage{"reads": json.RawMessage(`{"cfg/prod":"*"}`)}
	enrolled.Profile = "enrollment"
	for name, b := range map[string]coffre.Binding{"uploaded keys": keys, "reads": reads, "an enrollment": enrolled} {
		if unsaid(b) == "" {
			t.Errorf("%s is imported", name)
		}
	}
}
