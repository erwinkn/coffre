package coffre

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func saved(t *testing.T, content string) string {
	t.Helper()
	file := CredentialsFile(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

const origin = "https://secrets.acme.example"
const sessionToken = "coffre_cli_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestReadSessionTakesAPersonsOnly(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	person := `{"version":2,"current":"` + origin + `","instances":{"` + origin + `":{"mode":"signin","token":"` + sessionToken + `","principal":{"type":"user","id":"Ada@acme.example"},"expiresAt":"2026-12-27T12:00:00.000Z","obtainedAt":"2026-11-27T12:00:00Z"}}}`
	got, err := ReadSession(saved(t, person), origin, now)
	if err != nil || got.Token != sessionToken || got.Member != "user:ada@acme.example" {
		t.Fatalf("a person's session read as %+v, %v", got, err)
	}
	for _, refused := range []struct{ name, content, said string }{
		{"a service token's", strings.Replace(person, `"mode":"signin"`, `"mode":"signin","kind":"token"`, 1), "a service token's, not a person's"},
		{"a CI run's", strings.Replace(person, `"mode":"signin"`, `"mode":"signin","kind":"run"`, 1), "a CI run's, not a person's"},
		{"0.14's behind Access", strings.Replace(person, `"mode":"signin"`, `"mode":"cloudflare"`, 1), "not one coffre 0.16 signs in with"},
		{"another instance's", strings.ReplaceAll(person, origin, "https://other.acme.example"), "no session is saved for " + origin},
		{"ended", strings.Replace(person, "2026-12-27T12:00:00.000Z", "2026-11-27T11:59:59.000Z", 1), "ended on 2026-11-27"},
		{"no token", strings.Replace(person, `"token":"`+sessionToken+`",`, "", 1), "not one coffre 0.16 signs in with"},
		{"not the CLI's", `{"version":1}`, "not a credentials file"},
		{"not JSON", `coffre_cli_` + strings.Repeat("B", 43), "not a credentials file"},
	} {
		file := saved(t, refused.content)
		_, err := ReadSession(file, origin, now)
		if err == nil || !strings.Contains(err.Error(), refused.said) {
			t.Errorf("%s: %v", refused.name, err)
			continue
		}
		// What it says names the file and the instance, and nothing in the file.
		if strings.Contains(err.Error(), "coffre_cli_") || !strings.Contains(err.Error(), "coffre login") {
			t.Errorf("%s: %v", refused.name, err)
		}
	}
	if _, err := ReadSession(filepath.Join(t.TempDir(), "none.json"), origin, now); err == nil || !strings.Contains(err.Error(), "no coffre session is saved") {
		t.Errorf("no file: %v", err)
	}
}

func TestEndedSessionSaysToLogInAgain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer "+sessionToken {
			t.Errorf("sent %q", r.Header.Get("authorization"))
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","message":"sign in again"}`))
	}))
	defer server.Close()
	client := New(server.URL, &Session{Token: sessionToken}, "test")
	_, err := client.Project(context.Background(), "billing", false)
	if !Is(err, http.StatusUnauthorized, "") || !strings.Contains(err.Error(), "run `coffre login "+server.URL+"` again") || strings.Contains(err.Error(), sessionToken) {
		t.Fatalf("an ended session: %v", err)
	}
}

func TestWantedSaysWhatItReplaces(t *testing.T) {
	end := "2030-12-31T23:59:59.999Z"
	got := changes(map[string]Wanted{
		"billing":      {Role: "viewer"},
		"billing/prod": {Role: "developer", Was: &Held{Role: "viewer", Until: &end}},
		"web":          {},
	})
	if got["web"] != nil {
		t.Errorf("a revocation is %v", got["web"])
	}
	made := got["billing"].(map[string]any)
	if made["role"] != "viewer" || made["until"] != nil || made["was"] != nil {
		t.Errorf("a grant over nothing is %v", made)
	}
	changed := got["billing/prod"].(map[string]any)
	was := changed["was"].(map[string]any)
	if changed["role"] != "developer" || was["role"] != "viewer" || *(was["until"].(*string)) != end {
		t.Errorf("a grant over one held is %v", changed)
	}
}
