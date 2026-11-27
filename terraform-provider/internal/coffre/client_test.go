package coffre

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	value = "canary-value-0123456789"
	token = "coffre_svc_canary-token"
)

// fake is a coffre that answers each request with `answer`, and remembers what it was sent.
type fake struct {
	*httptest.Server
	mu     sync.Mutex
	asked  []asked
	answer func(n int, r *http.Request, body []byte) (int, http.Header, string)
}

type asked struct {
	Method, Path, Authorization string
	Body                        []byte
}

func newFake(t *testing.T, answer func(n int, r *http.Request, body []byte) (int, http.Header, string)) *fake {
	f := &fake{answer: answer}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.asked = append(f.asked, asked{r.Method, r.URL.EscapedPath(), r.Header.Get("authorization"), body})
		n := len(f.asked)
		f.mu.Unlock()
		status, header, text := f.answer(n, r, body)
		for name, values := range header {
			w.Header()[name] = values
		}
		w.WriteHeader(status)
		io.WriteString(w, text)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fake) calls() []asked {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]asked(nil), f.asked...)
}

// client is a client of the fake, whose sleeps are recorded, not slept.
func client(f *fake, signer Signer) (*Client, *[]time.Duration) {
	c := New(f.URL, signer, "test")
	var slept []time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	return c, &slept
}

func TestOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://secrets.acme.example":       "https://secrets.acme.example",
		"https://secrets.acme.example/":      "https://secrets.acme.example",
		" https://secrets.acme.example:8443": "https://secrets.acme.example:8443",
		"http://127.0.0.1:3000":              "http://127.0.0.1:3000",
		"http://localhost:3000":              "http://localhost:3000",
		"http://[::1]:3000":                  "http://[::1]:3000",
		"https://Secrets.ACME.example:443":   "https://secrets.acme.example",
		"http://localhost:80":                "http://localhost",
		"http://[::1]":                       "http://[::1]",
	} {
		if got, err := Origin(raw); err != nil || got != want {
			t.Errorf("Origin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"http://secrets.acme.example", "ftp://secrets.acme.example", "https://secrets.acme.example/api", "https://user:pass@secrets.acme.example", "https://secrets.acme.example?x=1", "secrets.acme.example", ""} {
		if got, err := Origin(raw); err == nil {
			t.Errorf("Origin(%q) = %q, and should be refused", raw, got)
		}
	}
	// Refused, credentials in a URL are not repeated.
	for _, raw := range []string{"https://user:pass@secrets.acme.example", "https://user:pa ss@secrets.acme.example", "https://:pass@secrets.acme.example/x"} {
		if _, err := Origin(raw); err == nil || strings.Contains(err.Error(), "pass") {
			t.Errorf("Origin(%q) says %v", raw, err)
		}
	}
}

func TestWriteSaysWhatItReplaces(t *testing.T) {
	f := newFake(t, func(int, *http.Request, []byte) (int, http.Header, string) {
		return 200, nil, `{"operationId":"op","keys":{"API_KEY":{"version":4,"sensitivity":"sensitive"}}}`
	})
	c, _ := client(f, Token(token))
	for _, replaces := range []Replaces{Nothing, Version("0b6d1c2e-0000-4000-8000-000000000001")} {
		written, err := c.Write(context.Background(), "bill ing", "prod", "API_KEY", value, "sensitive", replaces)
		if err != nil || written != (Written{Version: 4, Sensitivity: "sensitive"}) {
			t.Fatalf("Write = %+v, %v", written, err)
		}
	}
	calls := f.calls()
	var bodies []map[string]map[string]any
	for _, call := range calls {
		if call.Method != http.MethodPatch || call.Path != "/api/secrets/bill%20ing/prod" || call.Authorization != "Bearer "+token {
			t.Errorf("sent %s %s, %q", call.Method, call.Path, call.Authorization)
		}
		var body map[string]map[string]any
		json.Unmarshal(call.Body, &body)
		bodies = append(bodies, body)
	}
	// Nothing is `null`, said, not left out: a write that leaves it out replaces whatever the key holds.
	if replaces, said := bodies[0]["API_KEY"]["replaces"]; !said || replaces != nil {
		t.Errorf("a create says replaces %v (said: %v), not null", replaces, said)
	}
	if bodies[1]["API_KEY"]["replaces"] != "0b6d1c2e-0000-4000-8000-000000000001" || bodies[1]["API_KEY"]["value"] != value || bodies[1]["API_KEY"]["sensitivity"] != "sensitive" {
		t.Errorf("an update sends %v", bodies[1])
	}
}

func TestRefusalSaysNothingSent(t *testing.T) {
	f := newFake(t, func(int, *http.Request, []byte) (int, http.Header, string) {
		return 409, nil, `{"error":"conflict","reason":"stale","message":"it changed since it was listed"}`
	})
	c, _ := client(f, Token(token))
	_, err := c.Write(context.Background(), "tf", "prod", "API_KEY", value, "secret", Nothing)
	if !Is(err, 409, "stale") {
		t.Fatalf("Write = %v, not a 409 stale", err)
	}
	if text := err.Error(); strings.Contains(text, value) || strings.Contains(text, token) || text != "coffre answered 409 (conflict, stale): it changed since it was listed" {
		t.Errorf("the refusal says %q", text)
	}
	if len(f.calls()) != 1 {
		t.Errorf("a refused write was sent %d times", len(f.calls()))
	}
}

func TestNoRedirectIsFollowed(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	f := newFake(t, func(int, *http.Request, []byte) (int, http.Header, string) {
		return 307, http.Header{"Location": {other.URL + "/steal"}}, ""
	})
	c, _ := client(f, Token(token))
	_, err := c.Write(context.Background(), "tf", "prod", "API_KEY", value, "secret", Nothing)
	if err == nil || elsewhere.Load() != 0 {
		t.Errorf("a redirect was followed (%d requests elsewhere), or answered no error: %v", elsewhere.Load(), err)
	}
}

func TestWaitsWhenTold(t *testing.T) {
	// A GET is asked again on a 503 that says when; a write, only on a 429: a 503 may have come after it was made.
	for _, test := range []struct {
		name   string
		status int
		write  bool
		calls  int
	}{{"GET 503", 503, false, 2}, {"GET 429", 429, false, 2}, {"write 429", 429, true, 2}, {"write 503", 503, true, 1}} {
		t.Run(test.name, func(t *testing.T) {
			f := newFake(t, func(n int, r *http.Request, _ []byte) (int, http.Header, string) {
				if n == 1 {
					return test.status, http.Header{"Retry-After": {"3"}}, `{"error":"unavailable"}`
				}
				if r.Method == http.MethodGet {
					return 200, nil, `{"keys":[]}`
				}
				return 200, nil, `{"keys":{"K":{"version":1,"sensitivity":"secret"}}}`
			})
			c, slept := client(f, Token(token))
			var err error
			if test.write {
				_, err = c.Write(context.Background(), "tf", "prod", "K", value, "secret", Nothing)
			} else {
				_, err = c.Key(context.Background(), "tf", "prod", "K", false)
			}
			if got := len(f.calls()); got != test.calls {
				t.Errorf("sent %d times, not %d (%v)", got, test.calls, err)
			}
			if test.calls == 2 && (err != nil || len(*slept) != 1 || (*slept)[0] != 3*time.Second) {
				t.Errorf("waited %v, then %v", *slept, err)
			}
		})
	}
	t.Run("not past a minute", func(t *testing.T) {
		f := newFake(t, func(int, *http.Request, []byte) (int, http.Header, string) {
			return 429, http.Header{"Retry-After": {"25"}}, `{"error":"too_many_requests"}`
		})
		c, slept := client(f, Token(token))
		if _, err := c.Key(context.Background(), "tf", "prod", "K", false); !Is(err, 429, "") || len(*slept) != 2 {
			t.Errorf("waited %v, then %v", *slept, err)
		}
	})
	// Told to wait no time, a call still waits a second, and only a few times; told to wait past
	// a minute, or for longer than a Duration holds, it does not wait at all.
	for _, told := range []struct {
		after string
		waits []time.Duration
	}{
		{"0", []time.Duration{time.Second, time.Second, time.Second, time.Second, time.Second}},
		{"61", nil},
		{"9223372037", nil},
	} {
		t.Run("Retry-After: "+told.after, func(t *testing.T) {
			f := newFake(t, func(int, *http.Request, []byte) (int, http.Header, string) {
				return 429, http.Header{"Retry-After": {told.after}}, `{"error":"too_many_requests"}`
			})
			c, slept := client(f, Token(token))
			if _, err := c.Key(context.Background(), "tf", "prod", "K", false); !Is(err, 429, "") || !slices.Equal(*slept, told.waits) {
				t.Errorf("waited %v, then %v", *slept, err)
			}
		})
	}
}

func TestListingKeepsNoValue(t *testing.T) {
	f := newFake(t, func(_ int, r *http.Request, _ []byte) (int, http.Header, string) {
		if r.Method == http.MethodPatch {
			return 200, nil, `{"keys":{"REGION":{"version":3,"sensitivity":"plain"}}}`
		}
		return 200, nil, fmt.Sprintf(`{"keys":[{"key":"REGION","archived":false,"version":2,"versionId":"v2","secret":"s1","updatedBy":"token:x","sensitivity":"plain","value":%q,"reference":null,"parent":null}]}`, value)
	})
	c, _ := client(f, Token(token))
	ctx := context.Background()
	first, err := c.Key(ctx, "tf", "prod", "REGION", false)
	if err != nil || first == nil || *first.Version != 2 || !first.Own() {
		t.Fatalf("Key = %+v, %v", first, err)
	}
	if kept, _ := json.Marshal(first); strings.Contains(string(kept), value) {
		t.Errorf("the listing's plain value was kept: %s", kept)
	}
	// Listed once for both; a write there lists it again.
	c.Key(ctx, "tf", "prod", "OTHER", false)
	c.Write(ctx, "tf", "prod", "REGION", value, "plain", Version("v2"))
	c.Key(ctx, "tf", "prod", "REGION", false)
	var gets int
	for _, call := range f.calls() {
		if call.Method == http.MethodGet {
			gets++
		}
	}
	if gets != 2 {
		t.Errorf("listed %d times, not 2", gets)
	}
}

func TestListedStanding(t *testing.T) {
	id := "9726e640-0a12-4df1-b3f9-f6e7c76110e3"
	parent := func(state string) *struct {
		From  string `json:"from"`
		State string `json:"state"`
	} {
		return &struct {
			From  string `json:"from"`
			State string `json:"state"`
		}{"prod", state}
	}
	for _, test := range []struct {
		name                  string
		listed                Listed
		own, inherited, empty bool
	}{
		{"its own", Listed{VersionID: &id}, true, false, false},
		{"its own, with no value", Listed{}, true, false, true},
		{"an override", Listed{Parent: parent("overridden"), VersionID: &id}, true, false, false},
		{"passed down", Listed{Parent: parent("inherited"), VersionID: &id}, false, true, false},
		{"passed down, its version hidden", Listed{Parent: parent("inherited")}, false, true, false},
		{"removed", Listed{Parent: parent("removed")}, false, false, true},
		{"archived", Listed{Archived: true, VersionID: &id}, false, false, true},
		{"a reference", Listed{VersionID: &id, Reference: &struct {
			Source string `json:"source"`
		}{"tf/prod/A"}}, false, false, false},
	} {
		listed := test.listed
		if listed.Own() != test.own || listed.Inherited() != test.inherited || listed.Empty() != test.empty {
			t.Errorf("%s: own %v, inherited %v, empty %v", test.name, listed.Own(), listed.Inherited(), listed.Empty())
		}
	}
}

func TestArchiveOfNothingIsDone(t *testing.T) {
	f := newFake(t, func(int, *http.Request, []byte) (int, http.Header, string) {
		return 404, nil, `{"error":"not_found","message":"unknown secret"}`
	})
	c, _ := client(f, Token(token))
	if err := c.Archive(context.Background(), "tf", "prod", "GONE"); err != nil {
		t.Errorf("archiving a key that is not there: %v", err)
	}
	if call := f.calls()[0]; call.Method != http.MethodPatch || call.Path != "/api/secrets/tf/prod/GONE" || string(call.Body) != `{"archived":true}` {
		t.Errorf("sent %+v", call)
	}
}

// exchanges is a coffre whose /api/auth/oidc issues credentials of five minutes, `cred-1`, `cred-2`, …,
// and refuses an ID token traded before; whose other routes take only the newest credential.
func exchanges(t *testing.T) (*fake, *atomic.Int32) {
	var traded atomic.Int32
	spent := map[string]bool{}
	var mu sync.Mutex
	f := newFake(t, func(_ int, r *http.Request, body []byte) (int, http.Header, string) {
		if r.URL.Path == "/api/auth/oidc" {
			var asked struct{ Service, Token string }
			json.Unmarshal(body, &asked)
			mu.Lock()
			defer mu.Unlock()
			if asked.Service != "token:terraform" {
				return 401, nil, `{"error":"unauthenticated","reason":"unbound"}`
			}
			if spent[asked.Token] {
				return 401, nil, `{"error":"unauthenticated","reason":"replayed","message":"that ID token was used already"}`
			}
			spent[asked.Token] = true
			n := traded.Add(1)
			return 200, nil, fmt.Sprintf(`{"token":"cred-%d","expiresAt":%q}`, n, time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
		}
		if r.Header.Get("authorization") != fmt.Sprintf("Bearer cred-%d", traded.Load()) {
			return 401, nil, `{"error":"unauthenticated","message":"expired"}`
		}
		return 200, nil, `{"keys":[]}`
	})
	return f, &traded
}

// runner plays GitHub's: a fresh ID token, for the audience asked, each time.
type runner struct {
	n        atomic.Int32
	audience string
}

func (r *runner) Fresh() bool { return true }
func (r *runner) IDToken(_ context.Context, _ *Client, audience string) (string, error) {
	r.audience = audience
	return fmt.Sprintf("id-token-%d", r.n.Add(1)), nil
}

func TestOIDCTradesOnceAndRenews(t *testing.T) {
	f, traded := exchanges(t)
	now := time.Now()
	ids := &runner{}
	signer := &OIDC{Service: ServiceMember("terraform"), IDTokens: ids, Now: func() time.Time { return now }}
	c, _ := client(f, signer)
	ctx := context.Background()
	// Many at once, one exchange.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Key(ctx, "tf", fmt.Sprint("env", i), "K", true) }()
	}
	wg.Wait()
	if traded.Load() != 1 || ids.audience != f.URL {
		t.Fatalf("traded %d times, for %q", traded.Load(), ids.audience)
	}
	// Within a minute of its end, the credential is renewed before it is sent.
	now = now.Add(4*time.Minute + 30*time.Second)
	if _, err := c.Key(ctx, "tf", "prod", "K", true); err != nil || traded.Load() != 2 {
		t.Fatalf("near its end, traded %d times: %v", traded.Load(), err)
	}
	// Refused as expired, it is traded again, once, and the call made again.
	traded.Add(1)
	if _, err := c.Key(ctx, "tf", "prod", "K", true); err != nil || traded.Load() != 4 {
		t.Fatalf("refused, traded %d times: %v", traded.Load(), err)
	}
}

func TestGivenIDTokenServesOneExchange(t *testing.T) {
	f, _ := exchanges(t)
	now := time.Now()
	signer := &OIDC{Service: "token:terraform", IDTokens: GivenIDToken("id-token-given"), Now: func() time.Time { return now }}
	c, _ := client(f, signer)
	ctx := context.Background()
	if _, err := c.Key(ctx, "tf", "prod", "K", true); err != nil {
		t.Fatal(err)
	}
	// It cannot be renewed, so it serves its last minute too.
	now = now.Add(4*time.Minute + 30*time.Second)
	if _, err := c.Key(ctx, "tf", "prod", "K", true); err != nil {
		t.Fatalf("in its last minute, a given ID token's credential says %v", err)
	}
	now = now.Add(10 * time.Minute)
	_, err := c.Key(ctx, "tf", "prod", "K", true)
	if err == nil || !strings.Contains(err.Error(), "served its one exchange") || strings.Contains(err.Error(), "id-token-given") {
		t.Errorf("past its credential, a given ID token says %v", err)
	}
	// Spent by another run already, it says so.
	other, _ := client(f, &OIDC{Service: "token:terraform", IDTokens: GivenIDToken("id-token-given")})
	_, err = other.Key(ctx, "tf", "prod", "K", true)
	if err == nil || !strings.Contains(err.Error(), "traded already") || strings.Contains(err.Error(), "id-token-given") {
		t.Errorf("a spent ID token says %v", err)
	}
}

func TestServiceMember(t *testing.T) {
	for given, want := range map[string]string{"terraform": "token:terraform", "token:terraform": "token:terraform", " terraform ": "token:terraform"} {
		if got := ServiceMember(given); got != want {
			t.Errorf("ServiceMember(%q) = %q", given, got)
		}
	}
}

func TestActionsIDTokens(t *testing.T) {
	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "bearer request-token" || r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(401)
			return
		}
		fmt.Fprintf(w, `{"count":1,"value":"id-for-%s"}`, r.URL.Query().Get("audience"))
	}))
	defer runner.Close()
	c := New("https://secrets.acme.example", Token(""), "test")
	got, err := ActionsIDTokens{URL: runner.URL + "?api-version=2.0", Token: "request-token"}.IDToken(context.Background(), c, "https://secrets.acme.example")
	if err != nil || got != "id-for-https://secrets.acme.example" {
		t.Errorf("IDToken = %q, %v", got, err)
	}
	if _, err := (ActionsIDTokens{URL: runner.URL, Token: "wrong"}).IDToken(context.Background(), c, "x"); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("refused, it says %v", err)
	}
}
