package acceptance_test

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// checkLeaks holds the working directory to the rule: no value, token or ID
// token handed to Terraform is in anything it kept (state, its backup, a
// saved plan's every file) or said (each command's output, at TF_LOG=trace).
func (w *work) checkLeaks() {
	for _, leak := range w.leaks() {
		w.t.Error(leak)
	}
}

// leaks is each place a secret was found in, as "<where> holds <what>".
func (w *work) leaks() []string {
	var found []string
	secrets.Lock()
	known := make(map[string]string, len(secrets.all))
	for secret, what := range secrets.all {
		known[secret] = what
	}
	secrets.Unlock()
	look := func(where string, content []byte) {
		for secret, what := range known {
			if bytes.Contains(content, []byte(secret)) {
				found = append(found, where+" holds "+what)
			}
		}
		// A credential no test handed over: the one an OIDC sign-in is issued, say.
		if credential.Match(content) {
			found = append(found, where+" holds a coffre credential")
		}
	}
	look("the commands' output", w.said.Bytes())
	err := filepath.WalkDir(w.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, _ := filepath.Rel(w.dir, path)
		look(name, content)
		// A saved plan is a zip: each of its files, uncompressed.
		if reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content))); err == nil {
			for _, file := range reader.File {
				opened, err := file.Open()
				if err != nil {
					found = append(found, name+": "+file.Name+" did not open: "+err.Error())
					continue
				}
				inner, _ := io.ReadAll(opened)
				opened.Close()
				look(name+"!"+file.Name, inner)
			}
		} else if strings.HasSuffix(name, ".tfplan") {
			found = append(found, name+" is not a zip: "+err.Error())
		}
		return nil
	})
	if err != nil {
		found = append(found, "the working directory could not be read through: "+err.Error())
	}
	return found
}

// credential is any coffre token: its kind's prefix and 32 random bytes, in base64url (@coffre/core's identity/tokens.ts).
var credential = regexp.MustCompile(`coffre_(web|cli|svc|pat|use|wl|enr|mcp|mcr)_[A-Za-z0-9_-]{43}`)

// The check finds a secret where Terraform keeps one: a variable that is not ephemeral is kept in a
// saved plan, sensitive or not, which is why the docs declare every secret's variable ephemeral.
func TestLeakCheckFindsLeaks(t *testing.T) {
	each(t, func(t *testing.T, w *work, suffix string) {
		leaked := canary(t, "kept-in-the-plan"+suffix)
		w.write("", `variable "kept" {
  type      = string
  sensitive = true
}

resource "coffre_secret" "k" {
  project          = "tf"
  environment      = "prod"
  key              = "NEVER_MADE`+suffix+`"
  value_wo         = var.kept
  value_wo_version = 1
}
`)
		w.vars["kept"] = leaked
		w.must("plan", "-out=kept.tfplan")
		found := w.leaks()
		if !slices.ContainsFunc(found, func(leak string) bool {
			return strings.HasPrefix(leak, "kept.tfplan!") && strings.HasSuffix(leak, "kept-in-the-plan"+suffix)
		}) {
			t.Errorf("the check did not find the variable in the saved plan: %v", found)
		}
		if !strings.Contains(w.said.String(), "[TRACE]") {
			t.Error("the commands' output holds no trace: TF_LOG=trace did not reach them")
		}
		// Found, as it should be: the run's own check, at its end, would fail it.
		secrets.Lock()
		delete(secrets.all, leaked)
		secrets.Unlock()
	})
}
