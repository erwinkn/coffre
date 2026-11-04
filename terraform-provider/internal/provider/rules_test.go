package provider

import (
	"strings"
	"testing"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

func s(v string) *string { return &v }
func n(v int64) *int64   { return &v }

const id = "infra/prod/KEY"

// Section 5's table "What each change of the configuration plans".
func TestPlanUpdate(t *testing.T) {
	cases := []struct {
		name               string
		stateVersion, plan *string
		from, to           string
		natureKnown        bool
		parent             string
		want               changeKind
		problem            string
	}{
		{"value_wo_version changed", s("1"), s("2"), "secret", "secret", true, "", write, ""},
		{"value_wo_version and a looser nature", s("1"), s("2"), "sensitive", "secret", true, "", write, ""},
		{"value_wo_version unknown at plan", s("1"), nil, "secret", "secret", true, "", write, ""},
		{"imported: no value_wo_version in state", nil, s("1"), "secret", "secret", true, "", write, ""},
		{"stricter alone", s("1"), s("1"), "secret", "sensitive", true, "", mark, ""},
		{"plain to secret alone", s("1"), s("1"), "plain", "secret", true, "", mark, ""},
		{"looser alone", s("1"), s("1"), "sensitive", "secret", true, "", nothing, "writes its value again; change value_wo_version"},
		{"secret to plain alone", s("1"), s("1"), "secret", "plain", true, "", nothing, "writes its value again"},
		{"stricter on an inherited fork key", s("1"), s("1"), "secret", "sensitive", true, "inherited", nothing, "no value of its own to mark"},
		{"nature unknown at plan", s("1"), s("1"), "secret", "", false, "", mark, ""},
		{"nothing (on_destroy alone)", s("1"), s("1"), "secret", "secret", true, "", nothing, ""},
		{"nothing on an inherited key", s("1"), s("1"), "secret", "secret", true, "inherited", nothing, ""},
	}
	for _, c := range cases {
		got := planUpdate(id, c.stateVersion, c.plan, c.from, c.to, c.natureKnown, c.parent)
		if c.problem != "" {
			if !strings.Contains(got.Error, c.problem) {
				t.Errorf("%s: error %q, want one containing %q", c.name, got.Error, c.problem)
			}
			continue
		}
		if got.Error != "" || got.Kind != c.want {
			t.Errorf("%s: got %+v, want kind %d", c.name, got, c.want)
		}
	}
}

// A value_wo_version unknown at plan writes at apply only if it then differs from the state's.
func TestApplyUpdate(t *testing.T) {
	if got := applyUpdate(id, s("abc"), "abc", "secret", "secret", ""); got.Kind != nothing {
		t.Errorf("the same version once known: %+v", got)
	}
	if got := applyUpdate(id, s("abc"), "abd", "secret", "secret", ""); got.Kind != write {
		t.Errorf("a new version: %+v", got)
	}
	if got := applyUpdate(id, s("abc"), "abc", "secret", "sensitive", ""); got.Kind != mark {
		t.Errorf("the same version, stricter: %+v", got)
	}
	if got := applyUpdate(id, nil, "abc", "secret", "secret", ""); got.Kind != write {
		t.Errorf("imported: %+v", got)
	}
}

// Section 5's table "Values written outside Terraform".
func TestRefresh(t *testing.T) {
	own := func(versionID string) *coffre.Key {
		return &coffre.Key{Key: "KEY", Version: n(4), VersionID: s(versionID), UpdatedBy: s("ada@acme.example"), Sensitivity: s("sensitive")}
	}
	if got := refresh(id, own("v4"), kept{Written: "v4"}); got.Warning != "" || got.Error != "" || *got.VersionID != "v4" || *got.Sensitivity != "sensitive" {
		t.Errorf("Terraform's own version: %+v", got)
	}
	got := refresh(id, own("v5"), kept{Written: "v4"})
	if !strings.Contains(got.Warning, "written by ada@acme.example outside Terraform") || !strings.Contains(got.Warning, "change value_wo_version") || *got.VersionID != "v5" {
		t.Errorf("a version written by someone else: %+v", got)
	}
	if got := refresh(id, own("v5"), kept{}); got.Warning != "" {
		t.Errorf("imported, nothing written yet: no warning, got %+v", got)
	}
	if got := refresh(id, nil, kept{Written: "v4"}); !got.Remove {
		t.Errorf("no such key: %+v", got)
	}
	archived := own("v4")
	archived.Archived = true
	if got := refresh(id, archived, kept{}); !strings.Contains(got.Error, "archived in coffre") {
		t.Errorf("archived: %+v", got)
	}
	reference := own("v4")
	reference.Reference = []byte(`{"id":"r"}`)
	if got := refresh(id, reference, kept{}); !strings.Contains(got.Error, "a reference") {
		t.Errorf("a reference: %+v", got)
	}
	inherited := &coffre.Key{Key: "KEY", Version: n(2), VersionID: s("p2"), Sensitivity: s("secret"), Parent: &coffre.Parent{State: "inherited", From: "infra/prod"}}
	got = refresh(id, inherited, kept{Written: "v4", Parent: "overridden"})
	if !strings.Contains(got.Warning, "reads its parent's (infra/prod)") || got.Sensitivity != nil || got.Parent != "inherited" || *got.VersionID != "p2" {
		t.Errorf("an override reset to the parent's: %+v", got)
	}
	hidden := &coffre.Key{Key: "KEY", Parent: &coffre.Parent{State: "inherited", From: "infra/prod"}}
	if got := refresh(id, hidden, kept{}); got.VersionID != nil || got.Version != nil {
		t.Errorf("an inherited key whose parent's versions the credential is not told: %+v", got)
	}
	removed := &coffre.Key{Key: "KEY", Parent: &coffre.Parent{State: "removed", From: "infra/prod"}}
	if got := refresh(id, removed, kept{}); !strings.Contains(got.Error, "removed in this fork") {
		t.Errorf("removed: %+v", got)
	}
}

func TestCreatable(t *testing.T) {
	if replaces, problem := creatable(id, nil); replaces != nil || problem != "" {
		t.Errorf("absent: %v %q", replaces, problem)
	}
	if _, problem := creatable(id, &coffre.Key{Key: "KEY", VersionID: s("v1")}); !strings.Contains(problem, "exists in coffre; import it") {
		t.Errorf("live: %q", problem)
	}
	inherited := &coffre.Key{Key: "KEY", VersionID: s("p2"), Parent: &coffre.Parent{State: "inherited"}}
	if replaces, problem := creatable(id, inherited); problem != "" || replaces == nil || *replaces != "p2" {
		t.Errorf("inherited: an override over p2, got %v %q", replaces, problem)
	}
	if replaces, problem := creatable(id, &coffre.Key{Key: "KEY", Parent: &coffre.Parent{State: "inherited"}}); problem != "" || replaces != nil {
		t.Errorf("inherited, its version hidden: no replaces, got %v %q", replaces, problem)
	}
	if _, problem := creatable(id, &coffre.Key{Key: "KEY", Parent: &coffre.Parent{State: "removed"}}); !strings.Contains(problem, "removed in this fork") {
		t.Errorf("removed: %q", problem)
	}
	if _, problem := creatable(id, &coffre.Key{Key: "KEY", Archived: true}); !strings.Contains(problem, "archived") {
		t.Errorf("archived: %q", problem)
	}
}

// Section 3: exactly one way of signing in.
func TestSignInProblem(t *testing.T) {
	for _, c := range []struct {
		service, idToken, token bool
		ok                      bool
	}{
		{true, false, false, true},
		{true, true, false, true},
		{false, false, true, true},
		{false, false, false, false},
		{true, false, true, false},
		{false, true, false, false},
		{false, true, true, false},
		{true, true, true, false},
	} {
		if got := signInProblem(c.service, c.idToken, c.token) == ""; got != c.ok {
			t.Errorf("service=%v id_token=%v token=%v: ok=%v, want %v", c.service, c.idToken, c.token, got, c.ok)
		}
	}
}

func TestOriginOf(t *testing.T) {
	for raw, want := range map[string]string{
		"https://secrets.acme.example":     "https://secrets.acme.example",
		"https://secrets.acme.example/":    "https://secrets.acme.example",
		"http://127.0.0.1:3082":            "http://127.0.0.1:3082",
		"https://secrets.acme.example/api": "",
		"ftp://secrets.acme.example":       "",
		"secrets.acme.example":             "",
		"https://u:p@secrets.acme.example": "",
		"https://secrets.acme.example?x=1": "",
	} {
		if got, _ := originOf(raw); got != want {
			t.Errorf("%s: %q, want %q", raw, got, want)
		}
	}
}
