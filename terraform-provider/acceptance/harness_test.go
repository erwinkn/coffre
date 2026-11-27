// Acceptance tests: the provider, built, driven by real Terraform and OpenTofu
// binaries against a coffre deployment booted for the run
// (packages/conformance/scripts/terraform-fixture.ts). Run with TF_ACC=1, a
// Postgres as `pnpm conformance:workers` wants one, and `pnpm build` done.
// COFFRE_ACC_BINARIES lists the binaries, comma-separated (default: terraform
// and tofu, from PATH).
package acceptance_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture is what terraform-fixture.ts prints once it serves.
type fixture struct {
	URL     string `json:"url"`
	Service string `json:"service"`
	Token   string `json:"token"`
	Other   struct {
		Member string `json:"member"`
		Token  string `json:"token"`
	} `json:"other"`
	Actions struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	} `json:"actions"`
	// Grants is the account that manages access in cfg, apart from the one that writes secrets.
	Grants struct {
		Member string `json:"member"`
		Token  string `json:"token"`
	} `json:"grants"`
	// Member is someone to grant to.
	Member string `json:"member"`
	// Sessions are two people's `coffre login` sessions: the Owner's, and Dana's, a Developer of cfg.
	Sessions struct {
		Owner session `json:"owner"`
		Dana  session `json:"dana"`
	} `json:"sessions"`
	// Issuer is the dev IdP's, playing GitHub's for the runs it signs.
	Issuer string `json:"issuer"`
}

// session is a person's CLI session, as `coffre login` saves it.
type session struct {
	Member string `json:"member"`
	Token  string `json:"token"`
}

var (
	deployment fixture
	pluginDir  string
	binaries   []string
	// secrets is every value and credential the tests handed Terraform: none may appear in what it keeps or says.
	secrets = struct {
		sync.Mutex
		all map[string]string
	}{all: map[string]string{}}
)

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC") == "" {
		fmt.Println("acceptance tests skipped: set TF_ACC=1")
		os.Exit(0)
	}
	os.Exit(run(m))
}

func run(m *testing.M) int {
	for _, name := range strings.Split(envOr("COFFRE_ACC_BINARIES", "terraform,tofu"), ",") {
		found, err := exec.LookPath(strings.TrimSpace(name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "no %s: %v\n", name, err)
			return 1
		}
		binaries = append(binaries, found)
	}
	scratch, err := os.MkdirTemp("", "coffre-tf-acc-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(scratch)
	pluginDir = filepath.Join(scratch, "plugins")
	build := exec.Command("go", "build", "-o", filepath.Join(pluginDir, "terraform-provider-coffre"), "..")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "the provider did not build:", err)
		return 1
	}
	// Each try on ports of its own: another process may take one between the check and wrangler's bind.
	var stop func()
	for try := 0; try < 3; try++ {
		if stop, err = boot(); err == nil {
			break
		}
		fmt.Fprintln(os.Stderr, "the fixture did not boot, trying other ports:", firstLine(err.Error()))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer stop()
	remember("the service's token", deployment.Token)
	remember("the other token", deployment.Other.Token)
	remember("the grants account's token", deployment.Grants.Token)
	remember("the Owner's session", deployment.Sessions.Owner.Token)
	remember("Dana's session", deployment.Sessions.Dana.Token)
	return m.Run()
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// boot starts the fixture on a free run of three ports and waits for its line.
func boot() (func(), error) {
	port := freePorts()
	command := exec.Command("node", "--conditions=coffre:source", "packages/conformance/scripts/terraform-fixture.ts", "--port", fmt.Sprint(port))
	// The repository, whose fixture boots the deployment: this module's parent, unless COFFRE_ACC_REPO names another.
	command.Dir = envOr("COFFRE_ACC_REPO", filepath.Join("..", ".."))
	stdin, _ := command.StdinPipe()
	stdout, _ := command.StdoutPipe()
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("the fixture did not start: %w", err)
	}
	stop := func() {
		stdin.Close()
		done := make(chan struct{})
		go func() { command.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			command.Process.Kill()
		}
	}
	lines := make(chan string)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	timeout := time.After(5 * time.Minute)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				stop()
				return nil, fmt.Errorf("the fixture stopped before it served:\n%s", stderr.String())
			}
			if rest, found := strings.CutPrefix(line, "fixture "); found {
				if err := json.Unmarshal([]byte(rest), &deployment); err != nil {
					stop()
					return nil, fmt.Errorf("the fixture's line did not parse: %w", err)
				}
				// The scanner goes on reading what the fixture says; nothing else reads its stdout.
				go func() {
					for range lines {
					}
				}()
				return stop, nil
			}
		case <-timeout:
			stop()
			return nil, fmt.Errorf("the fixture did not serve in five minutes:\n%s", stderr.String())
		}
	}
}

func freePorts() int {
	for {
		port := 20000 + rand.IntN(20000)
		free := true
		for _, each := range []int{port, port + 1, port + 2} {
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", each))
			if err != nil {
				free = false
				break
			}
			listener.Close()
		}
		if free {
			return port
		}
	}
}

func remember(what, secret string) {
	if secret == "" {
		return
	}
	secrets.Lock()
	defer secrets.Unlock()
	secrets.all[secret] = what
}

// canary is a value no output would hold by chance, remembered as a secret.
func canary(t *testing.T, label string) string {
	value := fmt.Sprintf("canary-%s-%016x", label, rand.Uint64())
	remember("the value "+label, value)
	return value
}

// work is one Terraform working directory, and one binary.
type work struct {
	t    *testing.T
	bin  string
	dir  string
	vars map[string]string
	env  map[string]string
	// said is every command's output, which the leak check reads.
	said *bytes.Buffer
}

func newWork(t *testing.T, bin string) *work {
	dir := t.TempDir()
	config := filepath.Join(dir, "cli.tfrc")
	overrides := fmt.Sprintf(`provider_installation {
  dev_overrides {
    "registry.terraform.io/erwinkn/coffre" = %q
    "registry.opentofu.org/erwinkn/coffre" = %q
  }
  direct {}
}
`, pluginDir, pluginDir)
	if err := os.WriteFile(config, []byte(overrides), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &work{t: t, bin: bin, dir: dir, vars: map[string]string{}, env: map[string]string{"TF_CLI_CONFIG_FILE": config}, said: &bytes.Buffer{}}
	t.Cleanup(func() { w.checkLeaks() })
	return w
}

// write sets main.tf: the provider block signing in by token, unless `provider` is given, and `body`.
func (w *work) write(provider, body string) {
	if provider == "" {
		provider = fmt.Sprintf("provider \"coffre\" {\n  url   = %q\n  token = var.token\n}\n", deployment.URL)
		w.vars["token"] = deployment.Token
	}
	main := `terraform {
  required_providers {
    coffre = { source = "erwinkn/coffre" }
  }
}

variable "token" {
  type      = string
  default   = null
  sensitive = true
  ephemeral = true
}

variable "id_token" {
  type      = string
  default   = null
  sensitive = true
  ephemeral = true
}

variable "values" {
  type      = map(string)
  default   = {}
  sensitive = true
  ephemeral = true
}

` + provider + "\n" + body
	if err := os.WriteFile(filepath.Join(w.dir, "main.tf"), []byte(main), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

// signedIn is a provider block signing in with a service account's token.
func (w *work) signedIn(token string) string {
	w.vars["token"] = token
	return fmt.Sprintf("provider \"coffre\" {\n  url   = %q\n  token = var.token\n}\n", deployment.URL)
}

// as is a provider block signing in as a person, by the session `coffre login` saved: in a home
// directory of the run's own, outside the working directory, never the developer's.
func (w *work) as(who session) string {
	home := w.t.TempDir()
	saved := map[string]any{"version": 2, "current": deployment.URL, "instances": map[string]any{
		deployment.URL: map[string]any{"mode": "signin", "token": who.Token, "principal": map[string]string{"type": "user", "id": strings.TrimPrefix(who.Member, "user:")}, "obtainedAt": time.Now().UTC().Format(time.RFC3339)},
	}}
	raw, _ := json.Marshal(saved)
	if err := os.MkdirAll(filepath.Join(home, ".coffre"), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".coffre", "credentials.json"), raw, 0o600); err != nil {
		w.t.Fatal(err)
	}
	w.env["HOME"] = home
	return fmt.Sprintf("provider \"coffre\" {\n  url     = %q\n  session = true\n}\n", deployment.URL)
}

// value sets var.values[name], which resources read as their value_wo.
func (w *work) value(name, value string) {
	values := map[string]string{}
	if raw, ok := w.vars["values"]; ok {
		json.Unmarshal([]byte(raw), &values)
	}
	values[name] = value
	raw, _ := json.Marshal(values)
	w.vars["values"] = string(raw)
}

// tf runs one command, with every variable set and TF_LOG at trace, and says whether it succeeded.
func (w *work) tf(args ...string) (string, error) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, w.bin, args...)
	command.Dir = w.dir
	command.Env = append(os.Environ(), "TF_IN_AUTOMATION=1", "TF_INPUT=0", "TF_LOG=trace", "CHECKPOINT_DISABLE=1", "TF_CLI_ARGS=-no-color")
	for name, value := range w.env {
		command.Env = append(command.Env, name+"="+value)
	}
	for name, value := range w.vars {
		command.Env = append(command.Env, "TF_VAR_"+name+"="+value)
	}
	var out bytes.Buffer
	command.Stdout, command.Stderr = &out, &out
	err := command.Run()
	fmt.Fprintf(w.said, "\n$ %s %s\n%s", filepath.Base(w.bin), strings.Join(args, " "), out.String())
	return out.String(), err
}

// must runs a command that must succeed, and returns what it said without the trace.
func (w *work) must(args ...string) string {
	w.t.Helper()
	out, err := w.tf(args...)
	if err != nil {
		w.t.Fatalf("%s %s failed: %v\n%s", filepath.Base(w.bin), strings.Join(args, " "), err, untraced(out))
	}
	return untraced(out)
}

// fails runs a command that must fail, and returns what it said without the trace.
func (w *work) fails(args ...string) string {
	w.t.Helper()
	out, err := w.tf(args...)
	if err == nil {
		w.t.Fatalf("%s %s succeeded, and should not have:\n%s", filepath.Base(w.bin), strings.Join(args, " "), untraced(out))
	}
	return untraced(out)
}

var traceLine = regexp.MustCompile(`(?m)^\S*\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[.\d]*[-+Z][\d:]*\s+\[[A-Z]+\].*\n?`)

func untraced(out string) string { return traceLine.ReplaceAllString(out, "") }

// planned runs `plan -detailed-exitcode` and says whether it found changes.
func (w *work) planned() (bool, string) {
	w.t.Helper()
	out, err := w.tf("plan", "-detailed-exitcode", "-no-color")
	var exit *exec.ExitError
	switch {
	case err == nil:
		return false, untraced(out)
	case errorsAs(err, &exit) && exit.ExitCode() == 2:
		return true, untraced(out)
	}
	w.t.Fatalf("plan failed: %v\n%s", err, untraced(out))
	return false, ""
}

func errorsAs(err error, target **exec.ExitError) bool {
	exit, ok := err.(*exec.ExitError)
	if ok {
		*target = exit
	}
	return ok
}

// state is the resource's attributes, as `show -json` gives them.
func (w *work) state(address string) map[string]any {
	w.t.Helper()
	out, err := w.tf("show", "-json")
	if err != nil {
		w.t.Fatalf("show failed: %v\n%s", err, untraced(out))
	}
	var shown struct {
		Values struct {
			RootModule struct {
				Resources []struct {
					Address string         `json:"address"`
					Values  map[string]any `json:"values"`
				} `json:"resources"`
			} `json:"root_module"`
		} `json:"values"`
	}
	if err := json.Unmarshal([]byte(jsonOf(out)), &shown); err != nil {
		w.t.Fatalf("show -json did not parse: %v", err)
	}
	for _, resource := range shown.Values.RootModule.Resources {
		if resource.Address == address {
			return resource.Values
		}
	}
	return nil
}

// jsonOf is the one line of JSON in a command's output, among its trace.
func jsonOf(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "{") {
			return line
		}
	}
	return ""
}

// api calls coffre as someone else: the other service account, outside Terraform.
func api(t *testing.T, method, path string, body any, out any) int {
	t.Helper()
	return apiAs(t, deployment.Other.Token, method, path, body, out)
}

// apiAs calls coffre with a bearer credential of the fixture's.
func apiAs(t *testing.T, bearer, method, path string, body any, out any) int {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	request, _ := http.NewRequest(method, deployment.URL+"/api"+path, reader)
	request.Header.Set("authorization", "Bearer "+bearer)
	request.Header.Set("content-type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	if out != nil {
		json.Unmarshal(raw, out)
	}
	return response.StatusCode
}

// listed is a key as coffre lists it, to the other account.
type listed struct {
	Key         string  `json:"key"`
	Archived    bool    `json:"archived"`
	Version     *int64  `json:"version"`
	VersionID   *string `json:"versionId"`
	Sensitivity *string `json:"sensitivity"`
	Parent      *struct {
		State string `json:"state"`
	} `json:"parent"`
}

func key(t *testing.T, at, name string) *listed {
	t.Helper()
	var answer struct {
		Keys []listed `json:"keys"`
	}
	if status := api(t, http.MethodGet, "/secrets/"+at, nil, &answer); status != http.StatusOK {
		t.Fatalf("listing %s answered %d", at, status)
	}
	for _, each := range answer.Keys {
		if each.Key == name {
			return &each
		}
	}
	return nil
}

// revealed is a key's value, as the other account opens it.
func revealed(t *testing.T, at, name string) string {
	t.Helper()
	var answer struct {
		Values map[string]string `json:"values"`
	}
	if status := api(t, http.MethodPost, "/reveals", map[string]any{"path": at + "/" + name}, &answer); status != http.StatusOK {
		t.Fatalf("revealing %s/%s answered %d", at, name, status)
	}
	return answer.Values[name]
}

// set writes a key as the other account, outside Terraform.
func set(t *testing.T, at, name, value string) {
	t.Helper()
	if status := api(t, http.MethodPatch, "/secrets/"+at, map[string]any{name: value}, nil); status != http.StatusOK {
		t.Fatalf("writing %s/%s answered %d", at, name, status)
	}
}

// holds says whether a key's value is `want`, as the other account opens it. The vault remembers a use's
// rows for two seconds (`memorySeconds`), so a value written since may take that long to be read.
func holds(t *testing.T, at, name, want string) bool {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for {
		if revealed(t, at, name) == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	return line
}
