package acceptance_test

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// slugged is a test's suffix as a slug takes it: `_B0` is `-b0`.
func slugged(suffix string) string { return strings.ToLower(strings.ReplaceAll(suffix, "_", "-")) }

type listedEnvironment struct {
	Slug      string  `json:"slug"`
	Parent    *string `json:"parent"`
	Protected bool    `json:"protected"`
	Details   *struct {
		ArchivedAt *string `json:"archivedAt"`
	} `json:"details"`
}

// environmentOf is cfg's environment by slug, as the Owner lists it; nil when it lists none.
func environmentOf(t *testing.T, slug string) *listedEnvironment {
	t.Helper()
	var answer struct {
		Projects []struct {
			Slug         string              `json:"slug"`
			Environments []listedEnvironment `json:"environments"`
		} `json:"projects"`
	}
	if status := apiAs(t, deployment.Sessions.Owner.Token, http.MethodGet, "/projects", nil, &answer); status != http.StatusOK {
		t.Fatalf("listing the projects answered %d", status)
	}
	for _, project := range answer.Projects {
		for _, environment := range project.Environments {
			if project.Slug == "cfg" && environment.Slug == slug {
				return &environment
			}
		}
	}
	return nil
}

type listedGrant struct {
	Project     string  `json:"project"`
	Environment *string `json:"environment"`
	Role        string  `json:"role"`
	ExpiresAt   *string `json:"expiresAt"`
}

// accessOf is a member's standing and grants by place, as the Owner reads them.
func accessOf(t *testing.T, member string) (string, map[string]listedGrant) {
	t.Helper()
	var answer struct {
		Status string        `json:"status"`
		Grants []listedGrant `json:"grants"`
	}
	status := apiAs(t, deployment.Sessions.Owner.Token, http.MethodGet, "/members/"+url.PathEscape(member)+"/access", nil, &answer)
	if status == http.StatusNotFound {
		return "", nil
	}
	if status != http.StatusOK {
		t.Fatalf("reading %s's access answered %d", member, status)
	}
	grants := map[string]listedGrant{}
	for _, grant := range answer.Grants {
		at := grant.Project
		if grant.Environment != nil {
			at += "/" + *grant.Environment
		}
		grants[at] = grant
	}
	return answer.Status, grants
}

type listedBinding struct {
	ID     string         `json:"id"`
	Label  *string        `json:"label"`
	Claims map[string]any `json:"claims"`
	Policy map[string]any `json:"policy"`
}

func bindingsOf(t *testing.T, service string) []listedBinding {
	t.Helper()
	var answer struct {
		Bindings []listedBinding `json:"bindings"`
	}
	if status := apiAs(t, deployment.Sessions.Owner.Token, http.MethodGet, "/members/"+url.PathEscape(service)+"/bindings", nil, &answer); status != http.StatusOK {
		t.Fatalf("listing %s's bindings answered %d", service, status)
	}
	return answer.Bindings
}

// As the Owner, outside Terraform.
func owner(t *testing.T, method, path string, body any) {
	t.Helper()
	if status := apiAs(t, deployment.Sessions.Owner.Token, method, path, body, nil); status != http.StatusOK {
		t.Fatalf("%s %s as the Owner answered %d", method, path, status)
	}
}

// An environment's life: made, a fork of it made, protected, refused what coffre cannot do, imported, archived.
func TestEnvironment(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		base, fork := "base"+slugged(suffix), "fork"+slugged(suffix)
		config := func(protected bool, parent string) string {
			return fmt.Sprintf(`resource "coffre_environment" "base" {
  project   = "cfg"
  slug      = %q
  protected = %t
}

resource "coffre_environment" "fork" {
  project = "cfg"
  slug    = %q
  parent  = %s
}
`, base, protected, fork, parent)
		}
		provider := w.signedIn(deployment.Token)
		w.write(provider, config(false, "coffre_environment.base.slug"))
		w.must("apply", "-auto-approve")
		made := environmentOf(t, fork)
		expect(t, environmentOf(t, base) != nil && made != nil && made.Parent != nil && *made.Parent == base, "made, cfg lists %+v", made)
		expect(t, w.state("coffre_environment.fork")["id"] == "cfg/"+fork, "the fork's state is %v", w.state("coffre_environment.fork"))
		changes, out := w.planned()
		expect(t, !changes, "a plan with nothing changed plans changes:\n%s", out)

		w.write(provider, config(true, "coffre_environment.base.slug"))
		w.must("apply", "-auto-approve")
		expect(t, environmentOf(t, base).Protected, "protected, it lists %+v", environmentOf(t, base))

		// What coffre does not let this account do is refused at plan, saying why.
		w.write(provider, config(false, "coffre_environment.base.slug"))
		said := w.fails("plan")
		expect(t, strings.Contains(said, "stays protected") && strings.Contains(said, "Only an Owner of the project"), "unprotected by a service account, the plan says:\n%s", said)
		w.write(provider, config(true, `"prod"`))
		said = w.fails("plan")
		expect(t, strings.Contains(said, "its parent is fixed once made"), "another parent, the plan says:\n%s", said)

		// Forgotten and imported, it plans nothing.
		w.write(provider, config(true, "coffre_environment.base.slug"))
		w.must("state", "rm", "coffre_environment.base")
		w.must("import", "coffre_environment.base", "cfg/"+base)
		changes, out = w.planned()
		expect(t, !changes, "imported, the plan plans changes:\n%s", out)

		// Made in coffre already: refused, and told to import it.
		w.write(provider, config(true, "coffre_environment.base.slug")+fmt.Sprintf(`
resource "coffre_environment" "again" {
  project = "cfg"
  slug    = %q
}
`, base))
		said = w.fails("apply", "-auto-approve")
		expect(t, strings.Contains(said, "is in coffre already") && strings.Contains(said, "terraform import"), "made over one there, the apply says:\n%s", said)

		// Destroyed: the fork, then its parent, archived.
		w.write(provider, config(true, "coffre_environment.base.slug"))
		w.must("destroy", "-auto-approve")
		for _, slug := range []string{fork, base} {
			listed := environmentOf(t, slug)
			expect(t, listed != nil && listed.Details != nil && listed.Details.ArchivedAt != nil, "destroyed, %s lists %+v", slug, listed)
		}
	})
}

// A grant's life: made, changed, refused over a revocation made after its plan, made standing again
// after an end set by hand, refused over one made by hand, imported, revoked.
func TestGrant(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		env := "grant" + slugged(suffix)
		owner(t, http.MethodPut, "/projects/cfg/"+env, map[string]any{})
		at := "cfg/" + env
		grant := func(name, environment, role string) string {
			where := ""
			if environment != "" {
				where = fmt.Sprintf("  environment = %q\n", environment)
			}
			return fmt.Sprintf("resource \"coffre_grant\" %q {\n  member  = %q\n  project = \"cfg\"\n%s  role    = %q\n}\n", name, deployment.Member, where, role)
		}
		provider := w.signedIn(deployment.Grants.Token)
		w.write(provider, grant("eli", env, "viewer"))
		w.must("apply", "-auto-approve")
		_, grants := accessOf(t, deployment.Member)
		expect(t, grants[at].Role == "viewer", "made, %s holds %+v", deployment.Member, grants)
		expect(t, w.state("coffre_grant.eli")["id"] == at+"/"+deployment.Member, "the state is %v", w.state("coffre_grant.eli"))
		changes, out := w.planned()
		expect(t, !changes, "a plan with nothing changed plans changes:\n%s", out)

		w.write(provider, grant("eli", env, "developer"))
		w.must("apply", "-auto-approve")
		_, grants = accessOf(t, deployment.Member)
		expect(t, grants[at].Role == "developer", "changed, %s holds %+v", deployment.Member, grants)

		// A plan made, then the grant revoked in a hurry: the saved plan does not give it back.
		w.write(provider, grant("eli", env, "contributor"))
		w.must("plan", "-out=raise.tfplan")
		owner(t, http.MethodPatch, "/access/"+url.PathEscape(deployment.Member), map[string]any{at: nil})
		said := w.fails("apply", "raise.tfplan")
		expect(t, strings.Contains(said, "changed after this plan was made"), "applied over a revocation, the saved plan says:\n%s", said)
		_, grants = accessOf(t, deployment.Member)
		_, back := grants[at]
		expect(t, !back, "the saved plan gave the grant back: %+v", grants)
		// Planned again, the revocation shows, and the apply makes the grant again.
		w.must("apply", "-auto-approve")
		_, grants = accessOf(t, deployment.Member)
		expect(t, grants[at].Role == "contributor", "made again, %s holds %+v", deployment.Member, grants)

		// An end set by hand is drift: the apply makes the grant standing.
		owner(t, http.MethodPatch, "/access/"+url.PathEscape(deployment.Member), map[string]any{at: map[string]any{"role": "contributor", "until": "2030-12-31"}})
		changes, out = w.planned()
		expect(t, changes && strings.Contains(out, "2030-12-31"), "an end set by hand, the plan says:\n%s", out)
		w.must("apply", "-auto-approve")
		_, grants = accessOf(t, deployment.Member)
		expect(t, grants[at].Role == "contributor" && grants[at].ExpiresAt == nil, "made standing, %s holds %+v", deployment.Member, grants)

		// A grant made by hand is not taken over: imported instead.
		project := "cfg"
		owner(t, http.MethodPut, "/projects/cfg/"+env+"-hand", map[string]any{})
		hand := project + "/" + env + "-hand"
		owner(t, http.MethodPatch, "/access/"+url.PathEscape(deployment.Member), map[string]any{hand: "viewer"})
		w.write(provider, grant("eli", env, "contributor")+grant("hand", env+"-hand", "viewer"))
		said = w.fails("apply", "-auto-approve")
		expect(t, strings.Contains(said, "holds a grant at "+hand+" already") && strings.Contains(said, "terraform import"), "made over one made by hand, the apply says:\n%s", said)
		w.must("import", "coffre_grant.hand", hand+"/"+deployment.Member)
		changes, out = w.planned()
		expect(t, !changes, "imported, the plan plans changes:\n%s", out)

		w.must("destroy", "-auto-approve")
		_, grants = accessOf(t, deployment.Member)
		_, kept := grants[at]
		_, keptHand := grants[hand]
		expect(t, !kept && !keptHand, "destroyed, %s holds %+v", deployment.Member, grants)
	})
}

// A service account and its trust bindings, applied by a person: made, left alone, changed, its
// binding signing a run in, drifted, refused to a service's sign-in and to a person who does not
// manage it, removed.
func TestServiceAccount(t *testing.T) {
	remember("the runner's request token", deployment.Actions.Token)
	each(t, func(t *testing.T, w *work, suffix string) {
		name := "deploy" + slugged(suffix)
		service := "token:" + name
		config := func(grants, label string) string {
			return fmt.Sprintf(`resource "coffre_service_account" "deploy" {
  name   = %q
  grants = %s
}

resource "coffre_trust" "main" {
  service = coffre_service_account.deploy.member
  profile = "github"
  issuer  = %q
  claims = {
    repository_owner_id = "9919"
    repository_id       = "41532"
    workflow_ref        = "acme/api/.github/workflows/deploy.yml@refs/heads/main"
    ref                 = "refs/heads/main"
  }
  events = ["push"]
  label  = %q
}

resource "coffre_trust" "capy" {
  service        = coffre_service_account.deploy.member
  profile        = "custom"
  issuer         = %q
  claims         = { project = "2" }
  claim_prefixes = { sub = "org/1/project/2/" }
  policy         = { repeats = true, session_hours = 4 }
}
`, name, grants, deployment.Issuer, label, deployment.Issuer)
		}

		// Signed in as a service account, refused at plan, before coffre is asked anything.
		w.write(w.signedIn(deployment.Token), config(`{ cfg = "maintainer" }`, "main"))
		said := w.fails("plan")
		// Terraform plans no binding once its account is refused, so a binding alone, of an account there already, is refused as well.
		expect(t, strings.Contains(said, "coffre_service_account is applied by a person") && strings.Contains(said, "session = true"),
			"signed in by token, the plan says:\n%s", said)
		status, _ := accessOf(t, service)
		expect(t, status == "", "a refused plan made %s", service)
		w.write(w.signedIn(deployment.Token), fmt.Sprintf("resource \"coffre_trust\" \"alone\" {\n  service = %q\n  profile = \"custom\"\n  issuer  = %q\n  claims  = { project = \"2\" }\n}\n", deployment.Service, deployment.Issuer))
		said = w.fails("plan")
		expect(t, strings.Contains(said, "coffre_trust is applied by a person") && strings.Contains(said, "session = true"), "a binding signed in by token, the plan says:\n%s", said)

		person := w.as(deployment.Sessions.Owner)
		delete(w.vars, "token")
		w.write(person, config(`{ cfg = "maintainer" }`, "main"))
		w.must("apply", "-auto-approve")
		status, grants := accessOf(t, service)
		expect(t, status == "active" && len(grants) == 1 && grants["cfg"].Role == "maintainer", "made, %s is %s holding %+v", service, status, grants)
		bound := bindingsOf(t, service)
		expect(t, len(bound) == 2, "made, %s has bindings %+v", service, bound)
		sealed := fmt.Sprint(w.state("coffre_trust.main")["scope"])
		expect(t, sealed == "map[cfg:maintainer]", "made with no scope, the state records %s, not what coffre sealed", sealed)
		changes, out := w.planned()
		expect(t, !changes, "a plan with nothing changed plans changes:\n%s", out)

		// Its binding signs a CI run in: the run writes a secret as the account Terraform made.
		run := newWork(t, w.bin)
		run.env["ACTIONS_ID_TOKEN_REQUEST_URL"] = deployment.Actions.URL + "?api-version=2.0"
		run.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = deployment.Actions.Token
		written := canary(t, "by-the-run"+suffix)
		run.value("k", written)
		run.write(fmt.Sprintf("provider \"coffre\" {\n  url  = %q\n  oidc = { service = %q }\n}\n", deployment.URL, name), secret("k", "cfg/prod", "RUN"+suffix, 1, ""))
		run.must("apply", "-auto-approve")
		expect(t, run.state("coffre_secret.k")["updated_by"] == service, "the run wrote as %v", run.state("coffre_secret.k")["updated_by"])
		run.must("destroy", "-auto-approve")

		// Changed: a grant more, and the binding relabelled, which makes a new one in its place.
		first := w.state("coffre_trust.main")["id"]
		w.write(person, config(`{ cfg = "maintainer", "tf/prod" = "viewer" }`, "main, relabelled"))
		w.must("apply", "-auto-approve")
		_, grants = accessOf(t, service)
		expect(t, len(grants) == 2 && grants["tf/prod"].Role == "viewer", "changed, %s holds %+v", service, grants)
		bound = bindingsOf(t, service)
		replaced := w.state("coffre_trust.main")["id"]
		expect(t, len(bound) == 2 && replaced != first, "relabelled, %s has bindings %+v (was %v, now %v)", service, bound, first, replaced)
		// Made in place of the first, it reaches what that one did: the grant given since is not in its scope.
		sealed = fmt.Sprint(w.state("coffre_trust.main")["scope"])
		expect(t, sealed == "map[cfg:maintainer]", "relabelled, the state records the scope %s", sealed)
		changes, out = w.planned()
		expect(t, !changes, "changed, the plan plans changes:\n%s", out)

		// Drift: a binding removed and a grant made in coffre come back as the configuration says.
		owner(t, http.MethodDelete, "/members/"+url.PathEscape(service)+"/bindings/"+fmt.Sprint(replaced), nil)
		owner(t, http.MethodPatch, "/access/"+url.PathEscape(service), map[string]any{"tf/staging": "viewer"})
		changes, out = w.planned()
		expect(t, changes && strings.Contains(out, "coffre_trust.main will be created") && strings.Contains(out, "tf/staging"), "drifted, the plan says:\n%s", out)
		w.must("apply", "-auto-approve")
		_, grants = accessOf(t, service)
		_, extra := grants["tf/staging"]
		expect(t, !extra && len(bindingsOf(t, service)) == 2, "applied over drift, %s holds %+v", service, grants)

		// A person who does not manage it: the refresh fails, naming who can, and the state stays.
		before, _ := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
		dana := w.as(deployment.Sessions.Dana)
		w.write(dana, config(`{ cfg = "maintainer", "tf/prod" = "viewer" }`, "main, relabelled"))
		said = w.fails("plan")
		expect(t, strings.Contains(said, deployment.Sessions.Dana.Member+" does not manage "+service), "planned by Dana, the plan says:\n%s", said)
		after, _ := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
		expect(t, string(before) == string(after), "Dana's refused plan changed the state")

		// Destroyed: removed, and its bindings with it.
		w.as(deployment.Sessions.Owner)
		w.write(person, config(`{ cfg = "maintainer", "tf/prod" = "viewer" }`, "main, relabelled"))
		w.must("destroy", "-auto-approve")
		status, _ = accessOf(t, service)
		expect(t, status == "removed", "destroyed, %s is %q", service, status)
	})
}
