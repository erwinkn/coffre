package provider

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

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
	asked, known := shapeOf(ctx, github)
	if !known || !reflect.DeepEqual(asked, listedShape(listed)) {
		t.Fatalf("configured %+v, listed %+v", asked, listedShape(listed))
	}
	// Sent, the events are the profile's event claim, several as a list.
	sent := asked.binding("old")
	if !reflect.DeepEqual(sent.Claims["event_name"], []string{"push", "workflow_dispatch"}) || sent.Policy["sessionHours"] != nil || !reflect.DeepEqual(sent.Replaces, []string{"old"}) {
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
	asked, _ = shapeOf(ctx, capy)
	if !reflect.DeepEqual(asked, listedShape(listedCapy)) {
		t.Fatalf("configured %+v, listed %+v", asked, listedShape(listedCapy))
	}
	if sent := asked.binding(); !reflect.DeepEqual(sent.Claims["sub"], map[string]string{"prefix": "org/1/project/2/"}) || sent.Policy["repeats"] != true {
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
	again, _ := shapeOf(ctx, model)
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
