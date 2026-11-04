package acceptance

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// attributes are the resource's attributes in the workspace's state.
func attributes(t *testing.T, w *workspace, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Resources []struct {
			Type, Name string
			Instances  []struct {
				Attributes map[string]any `json:"attributes"`
			}
		}
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	for _, r := range state.Resources {
		if r.Type == "coffre_secret" && r.Name == name && len(r.Instances) == 1 {
			return r.Instances[0].Attributes
		}
	}
	return nil
}

func value(t *testing.T, label string) string {
	return "fake-" + label + "-" + strings.ToLower(unique(t, "v"))
}

// Create, then each change of section 5's table, each value read back by the verifier and held from everyone else as
// coffre's natures say; nothing of it in the state, nor in any record of a saved plan.
func TestLifecycle(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		key := unique(t, "LIFE")
		config := func(sensitivity, version, extra string) {
			w.configure(variables + provider(r.url(), "token") + secret("s", "prod", key, sensitivity, version, extra))
		}
		v1 := value(t, "one")
		config("secret", "1", "")
		w.ok(tokenVars(coffre.Tokens.Terraform, v1), "plan", "-out=create.tfplan")
		checkClean(t, w, "create.tfplan", v1)
		w.ok(tokenVars(coffre.Tokens.Terraform, v1), "apply", "create.tfplan")
		checkClean(t, w, "", v1)
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != v1 {
			t.Fatalf("the verifier read %q", got)
		}
		refused(t, coffre.Tokens.Terraform, "infra/prod", key)
		if got, _ := reveal(t, "", "infra/prod", key); got != v1 {
			t.Errorf("the Owner reads a secret: got %q", got)
		}

		// Stricter alone: a mark, no value sent, guarded by the version the plan saw.
		before := attributes(t, w, "s")["version_id"]
		config("sensitive", "1", "")
		at := r.mark()
		w.ok(tokenVars(coffre.Tokens.Terraform, v1), "apply", "-auto-approve")
		marks := patches(r.since(at))
		if len(marks) != 1 {
			t.Fatalf("a stricter sensitivity made %d writes", len(marks))
		}
		sent, _ := marks[0].body[key].(map[string]any)
		if _, ok := sent["value"]; ok || sent["replaces"] != before || sent["sensitivity"] != "sensitive" {
			t.Errorf("the mark sent %v", sent)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != v1 {
			t.Errorf("the mark changed the value: %q", got)
		}
		refused(t, "", "infra/prod", key)

		// Looser alone is refused at plan; with a new version it writes the value again.
		config("secret", "1", "")
		w.fails("making infra/prod/"+key+" secret writes its value again; change value_wo_version in the same apply", tokenVars(coffre.Tokens.Terraform, v1), "plan")
		v2 := value(t, "two")
		config("secret", "2", "")
		w.ok(tokenVars(coffre.Tokens.Terraform, v2), "plan", "-out=rotate.tfplan")
		checkClean(t, w, "rotate.tfplan", v2)
		w.ok(tokenVars(coffre.Tokens.Terraform, v2), "apply", "rotate.tfplan")
		if got, _ := reveal(t, "", "infra/prod", key); got != v2 {
			t.Errorf("the Owner reads the rewritten secret: got %q", got)
		}
		v3 := value(t, "three")
		config("plain", "3", "")
		w.ok(tokenVars(coffre.Tokens.Terraform, v3), "apply", "-auto-approve")
		if got, _ := reveal(t, "", "infra/prod", key); got != v3 {
			t.Errorf("the Owner reads a plain value: got %q", got)
		}
		checkClean(t, w, "", v3)

		// The write rule: on_destroy alone, and a refresh, call no PATCH, and version stays.
		version := attributes(t, w, "s")["version"]
		config("plain", "3", "  on_destroy = \"archive\"\n")
		at = r.mark()
		w.ok(tokenVars(coffre.Tokens.Terraform, "fake-ignored-0123456789"), "apply", "-auto-approve")
		w.ok(tokenVars(coffre.Tokens.Terraform, "fake-ignored-0123456789"), "apply", "-refresh-only", "-auto-approve")
		if writes := patches(r.since(at)); len(writes) != 0 {
			t.Errorf("on_destroy and a refresh wrote: %v", writes)
		}
		if got := attributes(t, w, "s")["version"]; got != version {
			t.Errorf("version moved from %v to %v", version, got)
		}
		if got, _ := reveal(t, "", "infra/prod", key); got != v3 {
			t.Errorf("a value given with no version change was written: %q", got)
		}
		if res := w.run(tokenVars(coffre.Tokens.Terraform, v3), "plan", "-detailed-exitcode"); res.code != 0 {
			t.Errorf("a plan after apply has changes (%d):\n%s", res.code, res.out)
		}

		// Destroy keeps the key, by default.
		config("plain", "3", "")
		w.ok(tokenVars(coffre.Tokens.Terraform, v3), "apply", "-auto-approve")
		out := w.ok(tokenVars(coffre.Tokens.Terraform, v3), "destroy", "-auto-approve")
		if !strings.Contains(unwrap(out), "on_destroy is \"keep\": Terraform no longer manages the key") {
			t.Errorf("destroy did not say it kept the key:\n%s", out)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != v3 {
			t.Errorf("destroy with keep lost the value: %q", got)
		}
	})
}

// Versions written outside Terraform: reported, not overwritten; one written between a saved plan and its apply stops
// the apply; an archived key fails the plan; a key gone is made again.
func TestDrift(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		key := unique(t, "DRIFT")
		config := func(sensitivity, version string) {
			w.configure(variables + provider(r.url(), "token") + secret("s", "prod", key, sensitivity, version, ""))
		}
		v1 := value(t, "one")
		config("secret", "1")
		w.ok(tokenVars(coffre.Tokens.Terraform, v1), "apply", "-auto-approve")

		hand := value(t, "hand")
		write(t, "infra/prod", key, map[string]any{"value": hand, "sensitivity": "secret"})
		at := r.mark()
		res := w.run(tokenVars(coffre.Tokens.Terraform, v1), "plan", "-detailed-exitcode")
		if res.code != 0 || !strings.Contains(unwrap(res.out), "written by rotator outside Terraform") {
			t.Errorf("a hand-written version: want a warning and no change (%d):\n%s", res.code, res.out)
		}
		if writes := patches(r.since(at)); len(writes) != 0 {
			t.Errorf("a plan wrote: %v", writes)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != hand {
			t.Errorf("the hand-written value was overwritten: %q", got)
		}

		// A value write and a mark, each planned and saved, then a version written before the apply: 409 stale.
		for _, step := range []struct{ sensitivity, version string }{{"secret", "2"}, {"sensitive", "1"}} {
			config(step.sensitivity, step.version)
			w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "two")), "plan", "-out=stale.tfplan")
			write(t, "infra/prod", key, map[string]any{"value": value(t, "between"), "sensitivity": "secret"})
			w.fails("infra/prod/"+key+" was written after this plan; plan again", tokenVars(coffre.Tokens.Terraform, value(t, "two")), "apply", "stale.tfplan")
			if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != value(t, "between") {
				t.Errorf("%v: the stale apply wrote: %q", step, got)
			}
		}

		// Archived in coffre: the plan fails.
		config("secret", "1")
		if status, answer := api(t, http.MethodPatch, "/api/secrets/infra/prod/"+key, "", map[string]any{"archived": true}); status != 200 {
			t.Fatalf("archive: %d %v", status, answer)
		}
		w.fails("infra/prod/"+key+" is archived in coffre", tokenVars(coffre.Tokens.Terraform, v1), "plan")
		if status, answer := api(t, http.MethodPatch, "/api/secrets/infra/prod/"+key, "", map[string]any{"archived": false}); status != 200 {
			t.Fatalf("unarchive: %d %v", status, answer)
		}

		// Gone (renamed away): the plan makes it again.
		if status, answer := api(t, http.MethodPatch, "/api/secrets/infra/prod/"+key, "", map[string]any{"key": key + "_OLD"}); status != 200 {
			t.Fatalf("rename: %d %v", status, answer)
		}
		res = w.run(tokenVars(coffre.Tokens.Terraform, v1), "plan", "-detailed-exitcode")
		if res.code != 2 || !strings.Contains(res.out, "will be created") {
			t.Errorf("a key gone from coffre: want a create (%d):\n%s", res.code, res.out)
		}
		w.ok(tokenVars(coffre.Tokens.Terraform, v1), "apply", "-auto-approve")
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != v1 {
			t.Errorf("made again: %q", got)
		}
	})
}

// A version written right after Terraform's own, before any list, still gives the warning: the receipt, not a list,
// names Terraform's version.
func TestReceipt(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		key := unique(t, "RECEIPT")
		written := false
		r.after = func(c call) {
			if c.method == http.MethodPatch && c.status == 200 && !written {
				written = true
				write(t, "infra/prod", key, map[string]any{"value": value(t, "right-after"), "sensitivity": "secret"})
			}
		}
		w.configure(variables + provider(r.url(), "token") + secret("s", "prod", key, "secret", "1", ""))
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "apply", "-auto-approve")
		r.after = nil
		res := w.run(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "plan", "-detailed-exitcode")
		if res.code != 0 || !strings.Contains(unwrap(res.out), "outside Terraform") {
			t.Errorf("want the warning, no change (%d):\n%s", res.code, res.out)
		}
	})
}

// A key Terraform writes in an inheriting fork: an override, guarded by the inherited version; reset to the parent's,
// reported; a mark refused at plan; written back on a version change; a removed key refused at plan and import.
func TestForks(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		key := unique(t, "FORK")
		write(t, "infra/prod", key, map[string]any{"value": value(t, "parent"), "sensitivity": "secret"})
		config := func(sensitivity, version string) {
			w.configure(variables + provider(r.url(), "token") + secret("s", "prod-eu", key, sensitivity, version, ""))
		}
		// The version a write over the inherited key names, as Terraform's credential is listed it (none if hidden).
		inheritedID := listed(t, coffre.Tokens.Terraform, "infra/prod-eu", key)["versionId"]
		config("secret", "1")
		at := r.mark()
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "apply", "-auto-approve")
		writes := patches(r.since(at))
		if len(writes) != 1 {
			t.Fatalf("%d writes", len(writes))
		}
		sent, _ := writes[0].body[key].(map[string]any)
		if sent["replaces"] != inheritedID {
			t.Errorf("the override replaces %v, the list showed %v", sent["replaces"], inheritedID)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod-eu", key); got != value(t, "one") {
			t.Errorf("the fork reads %q", got)
		}

		// Reset to the parent's: a warning, no write.
		if status, answer := api(t, http.MethodPatch, "/api/secrets/infra/prod-eu/"+key, "", map[string]any{"inherit": true}); status != 200 {
			t.Fatalf("reset: %d %v", status, answer)
		}
		at = r.mark()
		res := w.run(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "plan", "-detailed-exitcode")
		if res.code != 0 || !strings.Contains(unwrap(res.out), "the fork reads its parent's") {
			t.Errorf("a reset: want a warning, no change (%d):\n%s", res.code, res.out)
		}
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "apply", "-refresh-only", "-auto-approve")
		config("sensitive", "1")
		w.fails("has no value of its own to mark; change value_wo_version", tokenVars(coffre.Tokens.Terraform, value(t, "one")), "plan")
		if writes := patches(r.since(at)); len(writes) != 0 {
			t.Errorf("a reset key was written: %v", writes)
		}
		config("secret", "2")
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "two")), "apply", "-auto-approve")
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod-eu", key); got != value(t, "two") {
			t.Errorf("written back as an override: %q", got)
		}

		// A credential scoped to the fork alone is told no parent's version, and its override names none.
		other := unique(t, "FORKONLY")
		write(t, "infra/prod", other, map[string]any{"value": value(t, "parent"), "sensitivity": "secret"})
		alone := newWorkspace(t, w.cli)
		alone.configure(variables + provider(r.url(), "token") + secret("s", "prod-eu", other, "secret", "1", ""))
		told := listed(t, coffre.Tokens.Fork, "infra/prod-eu", other)
		if told == nil {
			t.Fatal("the fork lists nothing to its own credential")
		}
		at = r.mark()
		alone.ok(tokenVars(coffre.Tokens.Fork, value(t, "alone")), "apply", "-auto-approve")
		writes = patches(r.since(at))
		if len(writes) != 1 {
			t.Fatalf("%d writes", len(writes))
		}
		sent, _ = writes[0].body[other].(map[string]any)
		if sent["replaces"] != told["versionId"] {
			t.Errorf("a fork-only credential's override replaces %v; its list showed %v", sent["replaces"], told["versionId"])
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod-eu", other); got != value(t, "alone") {
			t.Errorf("the fork-only override reads %q", got)
		}

		// Reset again, so that the fork-only state holds no version: a saved plan to write it back, then an override by
		// hand before its apply. Nothing guards the write by version, so the apply checks the key again and stops.
		if status, answer := api(t, http.MethodPatch, "/api/secrets/infra/prod-eu/"+other, "", map[string]any{"inherit": true}); status != 200 {
			t.Fatalf("reset: %d %v", status, answer)
		}
		alone.ok(tokenVars(coffre.Tokens.Fork, value(t, "alone")), "apply", "-refresh-only", "-auto-approve")
		if id, ok := attributes(t, alone, "s")["version_id"]; !ok || id != nil {
			t.Fatalf("a fork-only credential's state holds version_id %v after the reset", id)
		}
		alone.configure(variables + provider(r.url(), "token") + secret("s", "prod-eu", other, "secret", "2", ""))
		alone.ok(tokenVars(coffre.Tokens.Fork, value(t, "again")), "plan", "-out=again.tfplan")
		hand := value(t, "hand")
		if status, answer := api(t, http.MethodPatch, "/api/secrets/infra/prod-eu", "", map[string]any{other: map[string]any{"value": hand, "sensitivity": "secret"}}); status != 200 {
			t.Fatalf("an override by hand: %d %v", status, answer)
		}
		at = r.mark()
		alone.fails("was written after this plan; plan again", tokenVars(coffre.Tokens.Fork, value(t, "again")), "apply", "again.tfplan")
		if writes := patches(r.since(at)); len(writes) != 0 {
			t.Errorf("the apply wrote over a version its plan did not see: %v", writes)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod-eu", other); got != hand {
			t.Errorf("the override by hand was overwritten: %q", got)
		}

		// Removed in the fork: refused at plan, and at import.
		removed := unique(t, "REMOVED")
		write(t, "infra/prod", removed, map[string]any{"value": value(t, "parent"), "sensitivity": "secret"})
		if status, answer := api(t, http.MethodPatch, "/api/projects/infra/prod-eu/dismissals", "", map[string]any{removed: true}); status != 200 {
			t.Fatalf("remove: %d %v", status, answer)
		}
		gone := newWorkspace(t, w.cli)
		gone.configure(variables + provider(r.url(), "token") + secret("s", "prod-eu", removed, "secret", "1", ""))
		gone.fails("removed in this fork: restore it there first", tokenVars(coffre.Tokens.Terraform, value(t, "x")), "plan")
		gone.fails("removed in this fork", tokenVars(coffre.Tokens.Terraform, value(t, "x")), "import", "coffre_secret.s", "infra/prod-eu/"+removed)
	})
}

// Destroy with archive: refused without secret.archive, the resource kept in state; archived with a credential of a
// role that holds it.
// A new key name replaces the resource: the new key is created under its own rules, whatever the old one's
// sensitivity, and the old key is kept.
func TestReplace(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		old, renamed := unique(t, "OLD"), unique(t, "NEW")
		w.configure(variables + provider(r.url(), "token") + secret("s", "prod", old, "secret", "1", ""))
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "old")), "apply", "-auto-approve")
		// Looser, the version unchanged: refused for the same key, a create for another.
		w.configure(variables + provider(r.url(), "token") + secret("s", "prod", renamed, "plain", "1", ""))
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "new")), "plan", "-out=replace.tfplan")
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "new")), "apply", "replace.tfplan")
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", renamed); got != value(t, "new") {
			t.Errorf("the new key reads %q", got)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", old); got != value(t, "old") {
			t.Errorf("the old key, kept, reads %q", got)
		}
		if a := attributes(t, w, "s"); a["key"] != renamed || a["sensitivity"] != "plain" {
			t.Errorf("the state after the replacement: %v", a)
		}
	})
}

func TestDestroyArchive(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		key := unique(t, "ARCHIVE")
		w.configure(variables + provider(r.url(), "token") + secret("s", "prod", key, "secret", "1", "  on_destroy = \"archive\"\n"))
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "apply", "-auto-approve")
		w.fails("may not do this here", tokenVars(coffre.Tokens.Terraform, value(t, "one")), "destroy", "-auto-approve")
		if out := w.ok(nil, "state", "list"); !strings.Contains(out, "coffre_secret.s") {
			t.Errorf("a refused archive dropped the resource from state:\n%s", out)
		}
		if got := listed(t, "", "infra/prod", key); got == nil || got["archived"] != false {
			t.Errorf("archived without the right: %v", got)
		}
		w.ok(nil, "state", "rm", "coffre_secret.s")

		archiver := newWorkspace(t, w.cli)
		other := unique(t, "ARCHIVED")
		archiver.configure(variables + provider(r.url(), "token") + secret("s", "prod", other, "secret", "1", "  on_destroy = \"archive\"\n"))
		archiver.ok(tokenVars(coffre.Tokens.Archiver, value(t, "one")), "apply", "-auto-approve")
		archiver.ok(tokenVars(coffre.Tokens.Archiver, value(t, "one")), "destroy", "-auto-approve")
		if got := listed(t, "", "infra/prod", other); got == nil || got["archived"] != true {
			t.Errorf("not archived: %v", got)
		}
	})
}

// A write where the account may write and the credential may not is refused, on each credential; a plan writes nothing.
func TestScope(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		runner := newRunner(t)
		key := unique(t, "SCOPE")
		block := strings.Replace(secret("s", "prod", key, "secret", "1", ""), `project          = "infra"`, `project          = "market"`, 1)
		for _, how := range []string{"token", "service", "id_token"} {
			w.configure(variables + provider(r.url(), how) + block)
			vars := tokenVars(coffre.Tokens.Terraform, value(t, "one"))
			switch how {
			case "service":
				vars = runner.vars(value(t, "one"))
			case "id_token":
				vars = map[string]string{"TF_VAR_coffre_id_token": mint(t), "TF_VAR_value": value(t, "one")}
			}
			at := r.mark()
			w.fails(`market/prod/`+key+`: the credential may not do this here: coffre answered 403`, vars, "plan")
			if writes := patches(r.since(at)); len(writes) != 0 {
				t.Errorf("%s: a plan wrote: %v", how, writes)
			}
		}
		if got := listed(t, "", "market/prod", key); got != nil {
			t.Errorf("written in market/prod: %v", got)
		}
	})
}

// terraform import adopts a key; the next apply writes Terraform's value as a new version. A create over a live key is refused.
func TestImport(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		key := unique(t, "IMPORT")
		write(t, "infra/prod", key, map[string]any{"value": value(t, "existing"), "sensitivity": "secret"})
		w.configure(variables + provider(r.url(), "token") + secret("s", "prod", key, "secret", "1", ""))
		w.fails("exists in coffre; import it", tokenVars(coffre.Tokens.Terraform, value(t, "one")), "plan")
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "import", "coffre_secret.s", "infra/prod/"+key)
		w.ok(tokenVars(coffre.Tokens.Terraform, value(t, "one")), "apply", "-auto-approve")
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != value(t, "one") {
			t.Errorf("after import and apply: %q", got)
		}
		if got := attributes(t, w, "s")["version"]; got != float64(2) {
			t.Errorf("version %v, want 2", got)
		}
	})
}

// Phases: a combined apply on the GitHub path trades twice and succeeds; on id_token it fails at its apply phase, and a
// saved plan with a token per phase succeeds. A credential that expires mid-apply is traded again.
func TestPhases(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		r := newRecorder(t)
		runner := newRunner(t)
		key := unique(t, "GITHUB")
		w.configure(variables + provider(r.url(), "service") + secret("s", "prod", key, "secret", "1", ""))
		at := r.mark()
		w.ok(runner.vars(value(t, "one")), "apply", "-auto-approve")
		if got := exchanges(r.since(at)); got != 2 {
			t.Errorf("a combined apply traded %d times, want 2 (plan, apply)", got)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != value(t, "one") {
			t.Errorf("GitHub path: %q", got)
		}

		// Expired mid-apply: coffre answers 401 once, and the provider trades again.
		w.configure(variables + provider(r.url(), "service") + secret("s", "prod", key, "secret", "2", ""))
		w.ok(runner.vars(value(t, "two")), "plan", "-out=expiry.tfplan")
		r.mu.Lock()
		r.refuse = 1
		r.mu.Unlock()
		at = r.mark()
		w.ok(runner.vars(value(t, "two")), "apply", "expiry.tfplan")
		if got := exchanges(r.since(at)); got != 2 {
			t.Errorf("an expired credential: %d trades in the apply, want 2", got)
		}
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", key); got != value(t, "two") {
			t.Errorf("after the expiry: %q", got)
		}

		other := unique(t, "IDTOKEN")
		tokens := newWorkspace(t, w.cli)
		tokens.configure(variables + provider(r.url(), "id_token") + secret("s", "prod", other, "secret", "1", ""))
		tokens.fails("this ID token was spent by the plan phase of this run; plan with -out and apply the saved plan with a fresh token",
			map[string]string{"TF_VAR_coffre_id_token": mint(t), "TF_VAR_value": value(t, "one")}, "apply", "-auto-approve")
		tokens.ok(map[string]string{"TF_VAR_coffre_id_token": mint(t), "TF_VAR_value": value(t, "one")}, "plan", "-out=phases.tfplan")
		tokens.ok(map[string]string{"TF_VAR_coffre_id_token": mint(t), "TF_VAR_value": value(t, "one")}, "apply", "phases.tfplan")
		if got, _ := reveal(t, coffre.Tokens.Verifier, "infra/prod", other); got != value(t, "one") {
			t.Errorf("id_token, a token per phase: %q", got)
		}
	})
}
