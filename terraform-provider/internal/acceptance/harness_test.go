// Package acceptance runs the provider through real Terraform and OpenTofu
// binaries against a local coffre (docs/design/terraform-provider.md,
// section 8), never a live instance:
//
//	TF_ACC=1 go test ./internal/acceptance -args -terraform=<path> -tofu=<path>
//
// The coffre is packages/conformance/scripts/terraform-fixture.ts: the Node
// example on SQLite, on ports of its own, seeded through the API.
package acceptance

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	terraformBinary = flag.String("terraform", "", "the terraform binary (1.11 or later)")
	tofuBinary      = flag.String("tofu", "", "the tofu binary (1.11 or later)")
	repoRoot        = flag.String("repo", "", "coffre's checkout, absolute or from terraform-provider/ (default: ..)")
	fixturePort     = flag.Int("port", 3482, "the fixture's coffre port; the dev IdP takes the next")
)

// fixture is what terraform-fixture.ts prints.
type fixture struct {
	Origin string `json:"origin"`
	Owner  struct {
		Cookie string `json:"cookie"`
	} `json:"owner"`
	Tokens struct {
		Terraform string `json:"terraform"`
		Fork      string `json:"fork"`
		Hand      string `json:"hand"`
		Verifier  string `json:"verifier"`
		Archiver  string `json:"archiver"`
	} `json:"tokens"`
	Workloads struct {
		Service      string `json:"service"`
		RequestURL   string `json:"requestUrl"`
		RequestToken string `json:"requestToken"`
		MintURL      string `json:"mintUrl"`
	} `json:"workloads"`
}

var (
	coffre    fixture
	pluginDir string // the provider's binary, for dev_overrides
	leakyDir  string // the leaking fixture provider's
)

// acceptance is whether TF_ACC=1 asked for the tests that boot coffre and run Terraform; the leak check's own tests run regardless.
var acceptance bool

func TestMain(m *testing.M) {
	flag.Parse()
	if acceptance = os.Getenv("TF_ACC") == "1"; !acceptance {
		os.Exit(m.Run())
	}
	os.Exit(run(m))
}

// needsAcceptance skips a test that boots coffre unless TF_ACC=1.
func needsAcceptance(t *testing.T) {
	if !acceptance {
		t.Skip("set TF_ACC=1 to run the acceptance tests")
	}
}

func run(m *testing.M) int {
	if *terraformBinary == "" && *tofuBinary == "" {
		fmt.Fprintln(os.Stderr, "give -terraform, -tofu or both")
		return 2
	}
	scratch, err := os.MkdirTemp("", "coffre-tf-acc-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(scratch)
	pluginDir, leakyDir = filepath.Join(scratch, "plugin"), filepath.Join(scratch, "leaky")
	for dir, pkg := range map[string]string{pluginDir: "github.com/erwinkn/coffre/terraform-provider", leakyDir: "github.com/erwinkn/coffre/terraform-provider/internal/acceptance/leaky"} {
		name := "terraform-provider-coffre"
		if dir == leakyDir {
			name = "terraform-provider-leaky"
		}
		build := exec.Command("go", "build", "-o", filepath.Join(dir, name), pkg)
		build.Stdout, build.Stderr = os.Stderr, os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "building the providers:", err)
			return 1
		}
	}
	stop, err := startFixture()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer stop()
	return m.Run()
}

func startFixture() (func(), error) {
	// The module's root, terraform-provider/: what a relative -repo is read from, as a run from there writes it.
	_, file, _, _ := runtime.Caller(0)
	module := filepath.Join(filepath.Dir(file), "..", "..")
	root := filepath.Join(module, "..")
	if *repoRoot != "" {
		root = *repoRoot
		if !filepath.IsAbs(root) {
			root = filepath.Join(module, root)
		}
	}
	cmd := exec.Command("node", "--conditions=coffre:source", "packages/conformance/scripts/terraform-fixture.ts", "examples/node", "--port", fmt.Sprint(*fixturePort))
	cmd.Dir = root
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the fixture: %w", err)
	}
	stop := func() {
		_ = stdin.Close()
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
		}
	}
	lines := bufio.NewScanner(stdout)
	lines.Buffer(make([]byte, 1<<20), 1<<20)
	for lines.Scan() {
		if line, ok := strings.CutPrefix(lines.Text(), "TERRAFORM_FIXTURE "); ok {
			if err := json.Unmarshal([]byte(line), &coffre); err != nil {
				stop()
				return nil, fmt.Errorf("the fixture's line does not read: %w", err)
			}
			go func() { _, _ = io.Copy(io.Discard, stdout) }()
			return stop, nil
		}
	}
	stop()
	return nil, fmt.Errorf("the fixture stopped before it seeded:\n%s", stderr.String())
}

// cli is one of the binaries the tests run on.
type cli struct{ name, path string }

func clis(t *testing.T) []cli {
	var out []cli
	if *terraformBinary != "" {
		out = append(out, cli{"terraform", *terraformBinary})
	}
	if *tofuBinary != "" {
		out = append(out, cli{"tofu", *tofuBinary})
	}
	return out
}

// eachCLI runs a test once per binary.
func eachCLI(t *testing.T, test func(t *testing.T, tf *workspace)) {
	needsAcceptance(t)
	for _, c := range clis(t) {
		t.Run(c.name, func(t *testing.T) { test(t, newWorkspace(t, c)) })
	}
}

// workspace is a Terraform working directory of its own.
type workspace struct {
	t    *testing.T
	cli  cli
	dir  string
	env  []string
	init bool
}

func newWorkspace(t *testing.T, c cli) *workspace {
	dir := t.TempDir()
	rc := filepath.Join(dir, "cli.tfrc")
	overrides := fmt.Sprintf("    \"erwinkn/coffre\" = %q\n    \"erwinkn/leaky\" = %q\n", pluginDir, leakyDir)
	if err := os.WriteFile(rc, []byte("provider_installation {\n  dev_overrides {\n"+overrides+"  }\n  direct {}\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := []string{"TF_CLI_CONFIG_FILE=" + rc, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1", "HOME=" + dir, "PATH=" + os.Getenv("PATH")}
	return &workspace{t: t, cli: c, dir: dir, env: env}
}

// result is a command's output and exit code.
type result struct {
	out  string
	code int
}

// run runs the binary with args, and the variables given (TF_VAR_*, the runner's).
func (w *workspace) run(vars map[string]string, args ...string) result {
	w.t.Helper()
	cmd := exec.Command(w.cli.path, append(args, "-no-color")...)
	cmd.Dir = w.dir
	cmd.Env = append([]string{}, w.env...)
	for name, value := range vars {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		w.t.Fatalf("%s %v: %v", w.cli.name, args, err)
	}
	return result{out.String(), code}
}

// ok runs a command that must succeed.
func (w *workspace) ok(vars map[string]string, args ...string) string {
	w.t.Helper()
	r := w.run(vars, args...)
	if r.code != 0 {
		w.t.Fatalf("%s %s failed (%d):\n%s", w.cli.name, strings.Join(args, " "), r.code, r.out)
	}
	return r.out
}

// fails runs a command that must fail, saying what matches pattern.
func (w *workspace) fails(pattern string, vars map[string]string, args ...string) string {
	w.t.Helper()
	r := w.run(vars, args...)
	if r.code == 0 {
		w.t.Fatalf("%s %s succeeded, want a failure matching %q:\n%s", w.cli.name, strings.Join(args, " "), pattern, r.out)
	}
	if !regexp.MustCompile(pattern).MatchString(unwrap(r.out)) {
		w.t.Fatalf("%s %s failed without %q:\n%s", w.cli.name, strings.Join(args, " "), pattern, r.out)
	}
	return r.out
}

// unwrap joins the lines Terraform wraps a diagnostic's text over.
func unwrap(out string) string { return regexp.MustCompile(`\s*\n\s*`).ReplaceAllString(out, " ") }

// configure writes main.tf.
func (w *workspace) configure(config string) {
	w.t.Helper()
	if err := os.WriteFile(filepath.Join(w.dir, "main.tf"), []byte(config), 0o600); err != nil {
		w.t.Fatal(err)
	}
	if !w.init {
		// With dev_overrides, init needs no registry; a fresh workspace has nothing else to install.
		w.init = true
	}
}

// provider is a provider block on url with a credential: "token", "service" (the GitHub path) or "id_token".
func provider(url, how string) string {
	switch how {
	case "service":
		return fmt.Sprintf("provider \"coffre\" {\n  url     = %q\n  service = %q\n}\n", url, coffre.Workloads.Service)
	case "id_token":
		return fmt.Sprintf("provider \"coffre\" {\n  url      = %q\n  service  = %q\n  id_token = var.coffre_id_token\n}\n", url, coffre.Workloads.Service)
	}
	return fmt.Sprintf("provider \"coffre\" {\n  url   = %q\n  token = var.coffre_token\n}\n", url)
}

const variables = `terraform {
  required_providers {
    coffre = { source = "erwinkn/coffre" }
  }
}
variable "coffre_token" {
  type      = string
  default   = null
  ephemeral = true
  sensitive = true
}
variable "coffre_id_token" {
  type      = string
  default   = null
  ephemeral = true
  sensitive = true
}
variable "value" {
  type      = string
  ephemeral = true
  sensitive = true
}
`

// secret is a coffre_secret block.
func secret(name, environment, key, sensitivity, version, extra string) string {
	return fmt.Sprintf("resource \"coffre_secret\" %q {\n  project          = \"infra\"\n  environment      = %q\n  key              = %q\n  sensitivity      = %q\n  value_wo         = var.value\n  value_wo_version = %q\n%s}\n",
		name, environment, key, sensitivity, version, extra)
}

// tokenVars are the variables of a run on a bearer token, with value.
func tokenVars(token, value string) map[string]string {
	return map[string]string{"TF_VAR_coffre_token": token, "TF_VAR_value": value}
}

// --- coffre, as the tests' other actors ---

// api calls coffre as a bearer, or as the Owner's session when bearer is "".
func api(t *testing.T, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request, _ := http.NewRequest(method, coffre.Origin+path, reader)
	request.Header.Set("content-type", "application/json")
	if bearer != "" {
		request.Header.Set("authorization", "Bearer "+bearer)
	} else {
		request.Header.Set("cookie", coffre.Owner.Cookie)
		request.Header.Set("origin", coffre.Origin)
		request.Header.Set("sec-fetch-site", "same-origin")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var answer map[string]any
	_ = json.NewDecoder(response.Body).Decode(&answer)
	return response.StatusCode, answer
}

// reveal reads key's value in place as bearer (or the Owner), or "" with the status refused.
func reveal(t *testing.T, bearer, place, key string) (string, int) {
	t.Helper()
	status, answer := api(t, http.MethodPost, "/api/reveals", bearer, map[string]any{"path": place + "/" + key})
	if status != 200 {
		return "", status
	}
	values, _ := answer["values"].(map[string]any)
	value, _ := values[key].(string)
	return value, status
}

// listed is key as place lists it to bearer.
func listed(t *testing.T, bearer, place, key string) map[string]any {
	t.Helper()
	status, answer := api(t, http.MethodGet, "/api/secrets/"+place, bearer, nil)
	if status != 200 {
		t.Fatalf("list %s: %d %v", place, status, answer)
	}
	keys, _ := answer["keys"].([]any)
	for _, k := range keys {
		if entry, ok := k.(map[string]any); ok && entry["key"] == key {
			return entry
		}
	}
	return nil
}

// write writes key by hand, as the hand service account.
func write(t *testing.T, place, key string, body any) {
	t.Helper()
	if status, answer := api(t, http.MethodPatch, "/api/secrets/"+place, coffre.Tokens.Hand, map[string]any{key: body}); status != 200 {
		t.Fatalf("writing %s/%s by hand: %d %v", place, key, status, answer)
	}
}

// --- a recording proxy in front of coffre ---

// recorder forwards every call to coffre, keeping what it was sent.
type recorder struct {
	mu     sync.Mutex
	calls  []call
	refuse int          // the next n API calls answer 401, as an expired credential
	after  func(c call) // run after each forwarded call, before it is answered
	server *httptest.Server
	target *url.URL
}

type call struct {
	method, path string
	body         map[string]any
	status       int
}

func newRecorder(t *testing.T) *recorder {
	target, _ := url.Parse(coffre.Origin)
	r := &recorder{target: target}
	r.server = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) url() string { return r.server.URL }

func (r *recorder) serve(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	c := call{method: req.Method, path: req.URL.Path}
	_ = json.Unmarshal(body, &c.body)
	r.mu.Lock()
	refuse := r.refuse > 0 && req.URL.Path != "/api/auth/oidc"
	if refuse {
		r.refuse--
	}
	r.mu.Unlock()
	if refuse {
		c.status = 401
		r.keep(c)
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"error":"unauthenticated","message":"that credential is unknown, expired or revoked"}`)
		return
	}
	forward, _ := http.NewRequestWithContext(context.Background(), req.Method, coffre.Origin+req.URL.RequestURI(), bytes.NewReader(body))
	forward.Header = req.Header.Clone()
	response, err := http.DefaultClient.Do(forward)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer response.Body.Close()
	answer, _ := io.ReadAll(response.Body)
	c.status = response.StatusCode
	r.keep(c)
	if r.after != nil {
		r.after(c)
	}
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(answer)
}

func (r *recorder) keep(c call) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}

// since returns the calls made after mark, and a new mark.
func (r *recorder) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *recorder) since(mark int) []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]call{}, r.calls[mark:]...)
}

// patches are the writes among calls.
func patches(calls []call) []call {
	var out []call
	for _, c := range calls {
		if c.method == http.MethodPatch {
			out = append(out, c)
		}
	}
	return out
}

// exchanges counts the OIDC exchanges among calls.
func exchanges(calls []call) int {
	count := 0
	for _, c := range calls {
		if c.path == "/api/auth/oidc" {
			count++
		}
	}
	return count
}

// --- the runner's ID tokens ---

// mint is an ID token of the dev IdP's GitHub run, for coffre's own origin.
func mint(t *testing.T) string {
	t.Helper()
	response, err := http.PostForm(coffre.Workloads.MintURL, url.Values{"aud": {coffre.Origin}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct{ Token string }
	_ = json.NewDecoder(response.Body).Decode(&body)
	if body.Token == "" {
		t.Fatalf("the dev IdP minted no token (%d)", response.StatusCode)
	}
	return body.Token
}

// runner is a GitHub job's ID token endpoint: it answers its bearer, as
// GitHub does, with a token for coffre's origin whatever audience the
// provider asks (it asks for the recorder's URL, which coffre's binding
// does not take). It counts what it was asked.
type runner struct {
	server *httptest.Server
	asked  []string
	mu     sync.Mutex
}

func newRunner(t *testing.T) *runner {
	r := &runner{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("authorization") != "bearer "+coffre.Workloads.RequestToken {
			http.Error(w, `{"message":"Bad credentials"}`, 401)
			return
		}
		r.mu.Lock()
		r.asked = append(r.asked, req.URL.Query().Get("audience"))
		r.mu.Unlock()
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"count": 1, "value": mint(t)})
	}))
	t.Cleanup(r.server.Close)
	return r
}

// vars are a GitHub job's variables, with value.
func (r *runner) vars(value string) map[string]string {
	return map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   r.server.URL + "/token?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": coffre.Workloads.RequestToken,
		"TF_VAR_value":                   value,
	}
}

// unique is a key name of this test's own: the tests share one coffre.
func unique(t *testing.T, base string) string {
	name := regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(t.Name(), "_")
	return strings.ToUpper(base + "_" + name)
}
