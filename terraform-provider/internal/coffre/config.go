package coffre

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
)

// Project is one project as GET /api/projects lists it, with only what the provider reads.
type Project struct {
	Slug         string        `json:"slug"`
	Permissions  []string      `json:"permissions"`
	Environments []Environment `json:"environments"`
}

// Environment is one of a project's environments, as the listing shows it.
type Environment struct {
	Slug          string  `json:"slug"`
	Parent        *string `json:"parent"`
	Protected     bool    `json:"protected"`
	Unprotectable bool    `json:"unprotectable"`
	Personal      bool    `json:"personal"`
	// Details is null for one the caller may only know by name.
	Details *struct {
		ArchivedAt *string `json:"archivedAt"`
	} `json:"details"`
}

// Archived says whether the listing shows it archived; one known by name only reads as not.
func (e Environment) Archived() bool { return e.Details != nil && e.Details.ArchivedAt != nil }

// May says whether the caller holds `permission` on the whole project.
func (p Project) May(permission string) bool {
	for _, held := range p.Permissions {
		if held == permission {
			return true
		}
	}
	return false
}

// Environment is one of its environments by slug, or nil.
func (p Project) Environment(slug string) *Environment {
	for _, environment := range p.Environments {
		if environment.Slug == slug && !environment.Personal {
			return &environment
		}
	}
	return nil
}

// projects remembers GET /api/projects for one Terraform operation: a refresh of fifty
// environments lists the projects once. A change of an environment forgets it.
type projects struct {
	mu    sync.Mutex
	known map[string]Project
	read  bool
}

// Project is the project by slug, as the caller's listing shows it, or nil when it shows none.
func (c *Client) Project(ctx context.Context, slug string, fresh bool) (*Project, error) {
	c.projects.mu.Lock()
	defer c.projects.mu.Unlock()
	if !c.projects.read || fresh {
		var answer struct {
			Projects []Project `json:"projects"`
		}
		if err := c.call(ctx, http.MethodGet, "/projects", nil, &answer); err != nil {
			return nil, err
		}
		c.projects.known = make(map[string]Project, len(answer.Projects))
		for _, project := range answer.Projects {
			c.projects.known[project.Slug] = project
		}
		c.projects.read = true
	}
	if found, ok := c.projects.known[slug]; ok {
		return &found, nil
	}
	return nil, nil
}

func (c *Client) forgetProjects() {
	c.projects.mu.Lock()
	defer c.projects.mu.Unlock()
	c.projects.read = false
}

// CreateEnvironment makes an environment: inheriting `parent`, or holding nothing when it is "".
func (c *Client) CreateEnvironment(ctx context.Context, project, slug, parent string) (Environment, error) {
	defer c.forgetProjects()
	body := map[string]any{}
	if parent != "" {
		body["from"], body["inherit"] = parent, true
	}
	var answer struct {
		Environment Environment `json:"environment"`
	}
	err := c.call(ctx, http.MethodPut, "/projects"+place(project, slug), body, &answer)
	return answer.Environment, err
}

// EditEnvironment makes one change of an environment (PATCH /api/projects/:project/:environment):
// `{"protected": true}`, `{"archived": true}`.
func (c *Client) EditEnvironment(ctx context.Context, project, slug string, change map[string]any) error {
	defer c.forgetProjects()
	return c.call(ctx, http.MethodPatch, "/projects"+place(project, slug), change, nil)
}

// Grant is one of a member's grants, as GET /api/members/:member/access shows it.
type Grant struct {
	Project     string  `json:"project"`
	Environment *string `json:"environment"`
	Role        string  `json:"role"`
	ExpiresAt   *string `json:"expiresAt"`
}

// Place is the grant's place by path: `billing`, or `billing/prod`.
func (g Grant) Place() string {
	if g.Environment == nil {
		return g.Project
	}
	return g.Project + "/" + *g.Environment
}

// Access is what GET /api/members/:member/access answers: the member's standing and the
// grants the caller may see. All of them when it runs the instance (`Scope` is then given) or
// manages the service account (`Managed`); else those at places where it manages access.
type Access struct {
	Status  string          `json:"status"`
	Managed bool            `json:"managed"`
	Scope   json.RawMessage `json:"scope"`
	Grants  []Grant         `json:"grants"`
}

// SeesAll says whether the answer holds every grant the member has.
func (a Access) SeesAll() bool {
	return a.Managed || (len(a.Scope) > 0 && string(a.Scope) != "null")
}

// At is the grant at a place, or nil.
func (a Access) At(at string) *Grant {
	for _, grant := range a.Grants {
		if grant.Place() == at {
			return &grant
		}
	}
	return nil
}

func memberPath(member string) string { return "/" + url.PathEscape(member) }

// Access reads one member's access; nil when coffre has no such member.
func (c *Client) Access(ctx context.Context, member string) (*Access, error) {
	var answer Access
	err := c.call(ctx, http.MethodGet, "/members"+memberPath(member)+"/access", nil, &answer)
	if Is(err, http.StatusNotFound, "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &answer, nil
}

// Held is a grant as a change says it replaces it: its role and end, or nothing (nil).
type Held struct {
	Role  string
	Until *string
}

// Wanted is one place of a change of grants: the role it should have, or none (Role ""), over
// what the plan saw there (`Was`, nil for nothing). A revocation is not guarded.
type Wanted struct {
	Role string
	Was  *Held
}

func (w Wanted) body() any {
	if w.Role == "" {
		return nil
	}
	var was any
	if w.Was != nil {
		was = map[string]any{"role": w.Was.Role, "until": w.Was.Until}
	}
	return map[string]any{"role": w.Role, "until": nil, "was": was}
}

func changes(wanted map[string]Wanted) map[string]any {
	body := make(map[string]any, len(wanted))
	for at, want := range wanted {
		body[at] = want.body()
	}
	return body
}

// SetAccess changes a member's grants at each place, all or none (PATCH /api/access/:member).
func (c *Client) SetAccess(ctx context.Context, member string, wanted map[string]Wanted) error {
	return c.call(ctx, http.MethodPatch, "/access"+memberPath(member), changes(wanted), nil)
}

// AdmitService admits a service account with its grants, all or none (PUT /api/members/:member),
// and says whether it admitted it: false for one that was active already, given the grants asked.
func (c *Client) AdmitService(ctx context.Context, member string, wanted map[string]Wanted) (bool, error) {
	var answer struct {
		Created bool `json:"created"`
	}
	err := c.call(ctx, http.MethodPut, "/members"+memberPath(member), map[string]any{"access": changes(wanted)}, &answer)
	return answer.Created, err
}

// RemoveMember removes a member (DELETE /api/members/:member): its grants revoked, its tokens,
// sessions and bindings ended. One that is not there is removed already.
func (c *Client) RemoveMember(ctx context.Context, member string) error {
	err := c.call(ctx, http.MethodDelete, "/members"+memberPath(member), nil, nil)
	if Is(err, http.StatusNotFound, "") || Is(err, http.StatusConflict, "removed") {
		return nil
	}
	return err
}

// Binding is one of a service account's trust bindings, as GET /api/members/:member/bindings lists it.
type Binding struct {
	ID      string                     `json:"id"`
	Profile string                     `json:"profile"`
	Issuer  string                     `json:"issuer"`
	Claims  map[string]json.RawMessage `json:"claims"`
	Scope   map[string]string          `json:"scope"`
	Policy  map[string]json.RawMessage `json:"policy"`
	// Keys are the ones a binding carries, null for one whose issuer's keys coffre fetches.
	Keys  json.RawMessage `json:"keys"`
	Label *string         `json:"label"`
}

// Bindings lists a service account's live bindings; nil, with no error, when the account is gone.
func (c *Client) Bindings(ctx context.Context, service string) ([]Binding, bool, error) {
	var answer struct {
		Bindings []Binding `json:"bindings"`
	}
	err := c.call(ctx, http.MethodGet, "/members"+memberPath(service)+"/bindings", nil, &answer)
	if Is(err, http.StatusNotFound, "unknown_principal") {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return answer.Bindings, true, nil
}

// NewBinding is a binding as POST /api/members/:member/bindings takes it.
type NewBinding struct {
	Profile string            `json:"profile"`
	Issuer  *string           `json:"issuer,omitempty"`
	Claims  map[string]any    `json:"claims"`
	Scope   map[string]string `json:"scope,omitempty"`
	// Policy is a workload's binding's, nil for a CI run's: a pointer, so that an empty one, coffre's
	// defaults, is still sent as {} and makes a workload's binding, never a bearer one.
	Policy   *map[string]any `json:"policy,omitempty"`
	Label    *string         `json:"label,omitempty"`
	Replaces []string        `json:"replaces,omitempty"`
}

// Bind makes a binding, ending those it replaces in the same change, and answers its id.
func (c *Client) Bind(ctx context.Context, service string, binding NewBinding) (BindingMade, error) {
	var answer struct {
		Binding BindingMade `json:"binding"`
	}
	if err := c.call(ctx, http.MethodPost, "/members"+memberPath(service)+"/bindings", binding, &answer); err != nil {
		return BindingMade{}, err
	}
	if answer.Binding.ID == "" {
		return BindingMade{}, fmt.Errorf("coffre's answer named no binding of %s", service)
	}
	return answer.Binding, nil
}

// BindingMade is a binding coffre made: its id, and the scope it sealed on it, by place and role.
type BindingMade struct {
	ID    string            `json:"id"`
	Scope map[string]string `json:"scope"`
}

// Unbind removes a binding, and what it issued with it. One that is not there, or whose account is
// gone with all its bindings, is removed already; any other 404 (an instance that trusts no
// workloads) is an error.
func (c *Client) Unbind(ctx context.Context, service, id string) error {
	err := c.call(ctx, http.MethodDelete, "/members"+memberPath(service)+"/bindings/"+url.PathEscape(id), nil, nil)
	if Is(err, http.StatusNotFound, "unknown_binding") || Is(err, http.StatusNotFound, "unknown_principal") {
		return nil
	}
	return err
}
