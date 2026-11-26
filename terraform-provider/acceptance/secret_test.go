package acceptance_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// each runs a test once per binary, with keys of its own: `KEY_B0`, `KEY_B1`.
func each(t *testing.T, test func(t *testing.T, w *work, suffix string)) {
	for i, bin := range binaries {
		version, _ := exec.Command(bin, "version").Output()
		label := filepath.Base(bin) + " " + strings.Fields(string(version) + " ? ?")[1]
		t.Run(label, func(t *testing.T) { test(t, newWork(t, bin), fmt.Sprintf("_B%d", i)) })
	}
}

// secret is one coffre_secret block, its value var.values[name].
func secret(name, at, key string, version int, sensitivity string) string {
	place := strings.SplitN(at, "/", 2)
	extra := ""
	if sensitivity != "" {
		extra = fmt.Sprintf("  sensitivity      = %q\n", sensitivity)
	}
	return fmt.Sprintf(`resource "coffre_secret" %q {
  project          = %q
  environment      = %q
  key              = %q
  value_wo         = var.values[%q]
  value_wo_version = %d
%s}
`, name, place[0], place[1], key, name, version, extra)
}

func expect(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func number(state map[string]any, name string) int64 {
	value, _ := state[name].(float64)
	return int64(value)
}

// A key's life: made, left alone, written again by version and by sensitivity, written outside
// Terraform and written back, refused from a stale saved plan, and archived.
func TestLifecycle(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		name := "LIFE" + suffix
		first := canary(t, "first"+suffix)
		w.value("k", first)
		w.write("", secret("k", "tf/prod", name, 1, ""))
		w.must("apply", "-auto-approve")
		state := w.state("coffre_secret.k")
		expect(t, state["id"] == "tf/prod/"+name && number(state, "version") == 1 && state["sensitivity"] == "secret" && state["updated_by"] == deployment.Service,
			"made, the state is %v", state)
		expect(t, state["value_wo"] == nil, "the state holds value_wo: %v", state["value_wo"])
		expect(t, holds(t, "tf/prod", name, first), "coffre does not hold the value written")
		changes, out := w.planned()
		expect(t, !changes, "a plan with nothing changed plans changes:\n%s", out)

		// A new version of the value.
		second := canary(t, "second"+suffix)
		w.value("k", second)
		w.write("", secret("k", "tf/prod", name, 2, ""))
		bumped := w.must("apply", "-auto-approve")
		expect(t, number(w.state("coffre_secret.k"), "version") == 2 && holds(t, "tf/prod", name, second), "the bumped value was not written: %v\n%s", w.state("coffre_secret.k"), bumped)

		// Sensitive: the value written again, as its next version.
		w.write("", secret("k", "tf/prod", name, 2, "sensitive"))
		w.must("apply", "-auto-approve")
		listed := key(t, "tf/prod", name)
		expect(t, *listed.Sensitivity == "sensitive" && *listed.Version == 3 && number(w.state("coffre_secret.k"), "version") == 3, "made sensitive, it lists %+v", listed)

		// Someone writes it outside Terraform: the plan says so, and the apply writes the configured value back.
		outside := canary(t, "outside"+suffix)
		set(t, "tf/prod", name, outside)
		changes, out = w.planned()
		expect(t, changes && strings.Contains(out, "tf/prod/"+name+" was written outside Terraform") && strings.Contains(out, "version 4, written by "+deployment.Other.Member),
			"drift was not planned, or not said:\n%s", out)
		w.must("apply", "-auto-approve")
		expect(t, holds(t, "tf/prod", name, second) && number(w.state("coffre_secret.k"), "version") == 5, "drift was not written back")
		changes, out = w.planned()
		expect(t, !changes, "after the drift was written back, the plan still plans changes:\n%s", out)

		// A saved plan, then someone writes: the plan's write is refused, and writes nothing.
		third := canary(t, "third"+suffix)
		w.value("k", third)
		w.write("", secret("k", "tf/prod", name, 3, "sensitive"))
		w.must("plan", "-out=stale.tfplan")
		w.must("show", "-json", "stale.tfplan")
		meanwhile := canary(t, "meanwhile"+suffix)
		set(t, "tf/prod", name, meanwhile)
		out = w.fails("apply", "stale.tfplan")
		expect(t, strings.Contains(out, "tf/prod/"+name+" changed after this plan was made"), "a stale plan's apply was not refused as stale:\n%s", out)
		expect(t, holds(t, "tf/prod", name, meanwhile), "a stale plan's apply wrote")
		w.must("apply", "-auto-approve")
		expect(t, holds(t, "tf/prod", name, third), "planned again, the value was not written")

		// Destroyed: archived, with its history. Made again, it is refused: coffre keeps the archived key under its name.
		w.must("destroy", "-auto-approve")
		listed = key(t, "tf/prod", name)
		expect(t, listed != nil && listed.Archived, "destroyed, the key is not archived: %+v", listed)
		out = w.fails("apply", "-auto-approve")
		expect(t, strings.Contains(out, "tf/prod/"+name+" is archived"), "made over an archived key, the refusal does not say so:\n%s", out)
	})
}

// An imported key: Terraform has never written it, so the first apply writes the configured value.
func TestImport(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		name := "IMPORTED" + suffix
		set(t, "tf/prod", name, canary(t, "before-import"+suffix))
		configured := canary(t, "imported"+suffix)
		w.value("k", configured)
		w.write("", secret("k", "tf/prod", name, 1, ""))
		w.must("import", "coffre_secret.k", "tf/prod/"+name)
		state := w.state("coffre_secret.k")
		expect(t, number(state, "version") == 1 && state["updated_by"] == deployment.Other.Member, "imported, the state is %v", state)
		changes, out := w.planned()
		expect(t, changes, "imported, the first plan writes nothing:\n%s", out)
		w.must("apply", "-auto-approve")
		expect(t, holds(t, "tf/prod", name, configured), "imported, the configured value was not written")
		changes, out = w.planned()
		expect(t, !changes, "imported and written, the plan still plans changes:\n%s", out)
		w.must("destroy", "-auto-approve")
	})
}

// Terraform makes only keys that hold nothing yet: one in coffre already is imported, never overwritten.
func TestExistingKey(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		name := "EXISTING" + suffix
		there := canary(t, "there"+suffix)
		set(t, "tf/prod", name, there)
		w.value("k", canary(t, "not-written"+suffix))
		w.write("", secret("k", "tf/prod", name, 1, ""))
		out := w.fails("apply", "-auto-approve")
		expect(t, strings.Contains(out, "tf/prod/"+name+" is in coffre already") && strings.Contains(out, "terraform import"), "the refusal does not say to import:\n%s", out)
		expect(t, holds(t, "tf/prod", name, there), "the key in coffre was overwritten")
	})
}

// In a fork, a key a parent passes down is overridden: staging gets a value of its own, prod keeps its.
func TestForkOverride(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		name := "OVERRIDDEN" + suffix
		parents := canary(t, "parents"+suffix)
		set(t, "tf/prod", name, parents)
		expect(t, key(t, "tf/staging", name).Parent.State == "inherited", "staging does not inherit the key")
		own := canary(t, "staging-own"+suffix)
		w.value("k", own)
		w.write("", secret("k", "tf/staging", name, 1, ""))
		w.must("apply", "-auto-approve")
		listed := key(t, "tf/staging", name)
		expect(t, listed.Parent != nil && listed.Parent.State == "overridden", "staging's key is not an override: %+v", listed)
		expect(t, holds(t, "tf/staging", name, own) && holds(t, "tf/prod", name, parents), "the override was not staging's alone")
		changes, out := w.planned()
		expect(t, !changes, "after the override, the plan still plans changes:\n%s", out)
		w.must("destroy", "-auto-approve")
	})
}

// In GitHub Actions, the provider signs in with a fresh ID token from the runner each time it needs one.
func TestActionsSignIn(t *testing.T) {
	remember("the runner's request token", deployment.Actions.Token)
	each(t, func(t *testing.T, w *work, suffix string) {
		name := "ACTIONS" + suffix
		w.env["ACTIONS_ID_TOKEN_REQUEST_URL"] = deployment.Actions.URL + "?api-version=2.0"
		w.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = deployment.Actions.Token
		configured := canary(t, "actions"+suffix)
		w.value("k", configured)
		w.write(fmt.Sprintf("provider \"coffre\" {\n  url  = %q\n  oidc = { service = \"terraform\" }\n}\n", deployment.URL), secret("k", "tf/prod", name, 1, ""))
		w.must("apply", "-auto-approve")
		expect(t, holds(t, "tf/prod", name, configured), "signed in by the run, the value was not written")
		changes, out := w.planned()
		expect(t, !changes, "signed in by the run, the plan plans changes:\n%s", out)
		w.must("destroy", "-auto-approve")
	})
}

// A given ID token serves one exchange: a saved plan and its apply take one each; an apply that plans too, two.
func TestGivenIDToken(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		name := "GIVEN" + suffix
		w.value("k", canary(t, "given"+suffix))
		w.write(fmt.Sprintf("provider \"coffre\" {\n  url  = %q\n  oidc = { service = \"token:terraform\", id_token = var.id_token }\n}\n", deployment.URL), secret("k", "tf/prod", name, 1, ""))
		w.vars["id_token"] = idToken(t)
		w.must("plan", "-out=made.tfplan")
		w.vars["id_token"] = idToken(t)
		w.must("apply", "made.tfplan")
		expect(t, key(t, "tf/prod", name) != nil, "the saved plan's apply made nothing")
		w.value("k", canary(t, "given-again"+suffix))
		w.write(fmt.Sprintf("provider \"coffre\" {\n  url  = %q\n  oidc = { service = \"token:terraform\", id_token = var.id_token }\n}\n", deployment.URL), secret("k", "tf/prod", name, 2, ""))
		w.vars["id_token"] = idToken(t)
		out := w.fails("apply", "-auto-approve")
		expect(t, strings.Contains(out, "traded already"), "an apply that plans too, on one ID token, does not say why it failed:\n%s", out)
		w.write("", secret("k", "tf/prod", name, 2, ""))
		w.must("destroy", "-auto-approve")
	})
}

// idToken asks the dev IdP for an ID token, as GitHub's runner gives one, for the deployment.
func idToken(t *testing.T) string {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, deployment.Actions.URL+"?audience="+deployment.URL, nil)
	request.Header.Set("authorization", "bearer "+deployment.Actions.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct {
		Value string `json:"value"`
	}
	if err := decode(response, &body); err != nil || body.Value == "" {
		t.Fatalf("no ID token: %v", err)
	}
	remember("an ID token", body.Value)
	return body.Value
}

// A value coffre would refuse is refused before any call, and the refusal says nothing of it.
func TestRefusedValue(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		long := canary(t, "long"+suffix)
		w.value("k", long+strings.Repeat("x", 70_000))
		remember("the long value", long+strings.Repeat("x", 70_000))
		w.write("", secret("k", "tf/prod", "REFUSED"+suffix, 1, ""))
		out := w.fails("apply", "-auto-approve")
		expect(t, strings.Contains(out, "Not a value coffre takes"), "a value over 64 KiB was not refused:\n%s", out)
		expect(t, key(t, "tf/prod", "REFUSED"+suffix) == nil, "a refused value was written")
	})
}

func decode(response *http.Response, out any) error {
	return json.NewDecoder(response.Body).Decode(out)
}

// A key made a reference outside Terraform is drift the provider does not write over: no write could
// say what it replaces. The plan says so, and the apply refuses and writes nothing.
func TestReferenceIsNotWrittenOver(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		name, source := "REFERRING"+suffix, "SOURCE"+suffix
		before := canary(t, "before-reference"+suffix)
		w.value("k", before)
		w.write("", secret("k", "tf/prod", name, 1, ""))
		w.must("apply", "-auto-approve")
		sourced := canary(t, "source"+suffix)
		set(t, "tf/prod", source, sourced)
		if status := api(t, http.MethodPatch, "/secrets/tf/prod", map[string]any{name: map[string]any{"ref": "tf/prod/" + source}}, nil); status != http.StatusOK {
			t.Fatalf("making %s a reference answered %d", name, status)
		}
		changes, out := w.planned()
		expect(t, changes && strings.Contains(out, "was written outside Terraform"), "the reference was not planned as drift:\n%s", out)
		out = w.fails("apply", "-auto-approve")
		expect(t, strings.Contains(out, "reads no version Terraform can replace"), "the apply over a reference does not say why it stops:\n%s", out)
		expect(t, holds(t, "tf/prod", name, sourced), "the reference was written over")
		// Broken in coffre, the reference leaves a key that holds nothing: the next plan makes it again.
		if status := api(t, http.MethodDelete, "/secrets/tf/prod/"+name+"/reference", nil, nil); status != http.StatusOK {
			t.Fatalf("breaking %s's reference answered %d", name, status)
		}
		changes, out = w.planned()
		expect(t, changes && strings.Contains(out, "will be created"), "the emptied key is not planned for creation:\n%s", out)
		w.must("apply", "-auto-approve")
		expect(t, holds(t, "tf/prod", name, before), "the emptied key was not written again")
	})
}
