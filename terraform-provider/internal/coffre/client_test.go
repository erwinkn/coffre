package coffre

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const value = "fake-secret-value-0123456789"

// fake is a coffre that records what it was asked.
type fake struct {
	mu        sync.Mutex
	calls     []string
	bodies    []string
	exchanges []string // the ID tokens traded, in order
	spent     map[string]bool
	expire    int // how many next calls answer 401
	write     func(body map[string]map[string]string) (int, string)
}

func (f *fake) server(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		f.calls = append(f.calls, r.Method+" "+r.URL.EscapedPath()+" "+r.Header.Get("authorization"))
		f.bodies = append(f.bodies, string(body))
		w.Header().Set("content-type", "application/json")
		if r.URL.Path == "/api/auth/oidc" {
			var asked struct{ Service, Token string }
			_ = json.Unmarshal(body, &asked)
			f.exchanges = append(f.exchanges, asked.Token)
			if f.spent[asked.Token] {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, `{"error":"unauthenticated","reason":"replayed","message":"this token was exchanged already"}`)
				return
			}
			f.spent[asked.Token] = true
			_, _ = io.WriteString(w, `{"token":"coffre_svc_from_`+asked.Token+`","expiresAt":"2026-11-04T00:05:00Z"}`)
			return
		}
		if f.expire > 0 {
			f.expire--
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"error":"unauthenticated","message":"that credential is unknown, expired or revoked"}`)
			return
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = io.WriteString(w, `{"keys":[{"key":"KEY","archived":false,"version":3,"versionId":"v3","updatedBy":"ada@acme.example","sensitivity":"plain","value":"`+value+`","reference":null,"parent":null}],"parents":[]}`)
		case http.MethodPatch:
			var patch map[string]map[string]string
			_ = json.Unmarshal(body, &patch)
			status, answer := 200, `{"operationId":"op","keys":{"KEY":{"version":4,"versionId":"v4","sensitivity":"secret"}}}`
			if f.write != nil {
				status, answer = f.write(patch)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, answer)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newFake() *fake { return &fake{spent: map[string]bool{}} }

func TestTokenIsSentAsBearer(t *testing.T) {
	f := newFake()
	server := f.server(t)
	client := New(server.URL, Auth{Token: "coffre_svc_given"}, nil, nil, "test")
	listing, err := client.List(context.Background(), "infra", "prod-eu@me")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.calls[0]; got != "GET /api/secrets/infra/prod-eu@me Bearer coffre_svc_given" {
		t.Errorf("call %q", got)
	}
	key := listing.Find("KEY")
	if key == nil || *key.VersionID != "v3" || *key.Version != 3 {
		t.Fatalf("listing %+v", listing)
	}
	// The list's plain value is dropped: no field of Key holds it.
	raw, _ := json.Marshal(key)
	if strings.Contains(string(raw), value) {
		t.Errorf("a listed plain value was kept: %s", raw)
	}
}

func TestWriteSendsReplacesAndReadsTheReceipt(t *testing.T) {
	f := newFake()
	server := f.server(t)
	client := New(server.URL, Auth{Token: "t"}, nil, nil, "test")
	v := value
	outcome, err := client.Set(context.Background(), "infra", "prod", "KEY", Write{Value: &v, Sensitivity: "secret", Replaces: ptr("v3")})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.VersionID != "v4" || outcome.Version != 4 {
		t.Errorf("outcome %+v", outcome)
	}
	var sent map[string]map[string]string
	_ = json.Unmarshal([]byte(f.bodies[0]), &sent)
	if sent["KEY"]["value"] != value || sent["KEY"]["replaces"] != "v3" || sent["KEY"]["sensitivity"] != "secret" {
		t.Errorf("sent %v", sent)
	}
	// A mark sends no value.
	if _, err := client.Set(context.Background(), "infra", "prod", "KEY", Write{Sensitivity: "sensitive", Replaces: ptr("v3")}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.bodies[1], `"value"`) {
		t.Errorf("a mark sent a value: %s", f.bodies[1])
	}
}

func TestStaleAndOldServers(t *testing.T) {
	f := newFake()
	f.write = func(map[string]map[string]string) (int, string) {
		return 409, `{"error":"conflict","reason":"stale","message":"KEY changed since it was listed"}`
	}
	server := f.server(t)
	client := New(server.URL, Auth{Token: "t"}, nil, nil, "test")
	v := value
	_, err := client.Set(context.Background(), "infra", "prod", "KEY", Write{Value: &v, Sensitivity: "secret", Replaces: ptr("v3")})
	if !IsStatus(err, 409, "stale") {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Errorf("an error carries the value: %v", err)
	}
	f.write = func(map[string]map[string]string) (int, string) {
		return 200, `{"operationId":"op","keys":{"KEY":{"version":4,"sensitivity":"secret"}}}`
	}
	if _, err := client.Set(context.Background(), "infra", "prod", "KEY", Write{Value: &v, Sensitivity: "secret"}); err == nil || !strings.Contains(err.Error(), "no versionId") {
		t.Errorf("a coffre that names no versionId: %v", err)
	}
}

func TestGitHubPathTradesAgainOn401(t *testing.T) {
	f := newFake()
	server := f.server(t)
	var asked []string
	var count int
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("audience")+" "+r.Header.Get("authorization"))
		count++
		_, _ = io.WriteString(w, `{"value":"gh-token-`+string(rune('0'+count))+`"}`)
	}))
	t.Cleanup(github.Close)
	runner := func(name string) string {
		return map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": github.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-bearer"}[name]
	}
	client := New(server.URL, Auth{Service: "terraform-infra"}, runner, nil, "test")
	if _, err := client.List(context.Background(), "infra", "prod"); err != nil {
		t.Fatal(err)
	}
	f.expire = 1
	if _, err := client.List(context.Background(), "infra", "prod"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.exchanges, ",") != "gh-token-1,gh-token-2" {
		t.Errorf("exchanges %v", f.exchanges)
	}
	if !strings.Contains(f.bodies[0], `"service":"token:terraform-infra"`) {
		t.Errorf("the exchange named %s", f.bodies[0])
	}
	if asked[0] != server.URL+" bearer runner-bearer" {
		t.Errorf("GitHub asked %q", asked[0])
	}
	// Once per credential: two 401s in a row fail.
	f.expire = 2
	if _, err := client.List(context.Background(), "infra", "prod"); !IsStatus(err, 401, "") {
		t.Errorf("a second 401: %v", err)
	}
}

func TestIDTokenServesOnePhase(t *testing.T) {
	f := newFake()
	server := f.server(t)
	plan := New(server.URL, Auth{Service: "terraform-infra", IDToken: "one-token"}, nil, nil, "test")
	if _, err := plan.List(context.Background(), "infra", "prod"); err != nil {
		t.Fatal(err)
	}
	// The apply phase: a new process, the same token.
	apply := New(server.URL, Auth{Service: "terraform-infra", IDToken: "one-token"}, nil, nil, "test")
	_, err := apply.List(context.Background(), "infra", "prod")
	if err == nil || err.Error() != SpentIDToken {
		t.Errorf("the apply phase: %v", err)
	}
	// Within a phase, an expired credential cannot trade the token again.
	f.expire = 1
	if _, err := plan.List(context.Background(), "infra", "prod"); err == nil || !strings.Contains(err.Error(), "spent once") {
		t.Errorf("expired mid-phase: %v", err)
	}
}

func TestNoIDTokenOffGitHub(t *testing.T) {
	client := New("http://127.0.0.1:1", Auth{Service: "terraform-infra"}, nil, nil, "test")
	if _, err := client.List(context.Background(), "infra", "prod"); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("no runner token: %v", err)
	}
}

func ptr(v string) *string { return &v }

func TestServiceMember(t *testing.T) {
	for given, want := range map[string]string{"terraform-infra": "token:terraform-infra", "service:terraform-infra": "token:terraform-infra", "token:terraform-infra": "token:terraform-infra", " deploy ": "token:deploy"} {
		if got := ServiceMember(given); got != want {
			t.Errorf("%q: %q, want %q", given, got, want)
		}
	}
}

// A write coffre redirects is refused, its value sent once, to the URL configured.
func TestRedirectIsNotFollowed(t *testing.T) {
	var elsewhere []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		elsewhere = append(elsewhere, string(body))
	}))
	t.Cleanup(other.Close)
	sent := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent++
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusPermanentRedirect)
	}))
	t.Cleanup(server.Close)
	client := New(server.URL, Auth{Token: "t"}, nil, nil, "test")
	v := value
	_, err := client.Set(context.Background(), "infra", "prod", "KEY", Write{Value: &v, Sensitivity: "secret"})
	if err == nil || !strings.Contains(err.Error(), "a redirect to") || !strings.Contains(err.Error(), other.URL) {
		t.Errorf("a redirected write: %v", err)
	}
	if sent != 1 || len(elsewhere) != 0 {
		t.Errorf("the write went %d times to coffre and %d elsewhere", sent, len(elsewhere))
	}
}

// failOnce fails its first request before it leaves, as a network would.
type failOnce struct{ failed bool }

func (f *failOnce) RoundTrip(r *http.Request) (*http.Response, error) {
	if !f.failed {
		f.failed = true
		return nil, io.ErrUnexpectedEOF
	}
	return http.DefaultTransport.RoundTrip(r)
}

// An exchange the network lost leaves the ID token unspent: the next call
// trades it, and the error before names the network, not a spent token.
func TestIDTokenIsSpentOnceCoffreSawIt(t *testing.T) {
	f := newFake()
	server := f.server(t)
	client := New(server.URL, Auth{Service: "terraform-infra", IDToken: "one-token"}, nil, &http.Client{Transport: &failOnce{}}, "test")
	_, err := client.List(context.Background(), "infra", "prod")
	if err == nil || strings.Contains(err.Error(), "spent once") || !strings.Contains(err.Error(), "/api/auth/oidc") {
		t.Errorf("the lost exchange: %v", err)
	}
	if _, err := client.List(context.Background(), "infra", "prod"); err != nil {
		t.Errorf("after the network came back: %v", err)
	}
	if len(f.exchanges) != 1 {
		t.Errorf("coffre saw %d exchanges", len(f.exchanges))
	}
}
