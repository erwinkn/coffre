package acceptance

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hidden = "fake-hidden-value-0123456789"

// The check finds a value however it is wrapped, and nothing where it is not.
func TestLeakCheckDecodesLayers(t *testing.T) {
	inner, _ := json.Marshal(map[string]string{"kept": base64.StdEncoding.EncodeToString([]byte(hidden))})
	state, _ := json.Marshal(map[string]any{"resources": []any{map[string]any{"instances": []any{map[string]any{"private": base64.StdEncoding.EncodeToString(inner)}}}}})
	var zipped bytes.Buffer
	archive := zip.NewWriter(&zipped)
	file, _ := archive.Create("tfstate")
	_, _ = file.Write(state)
	_ = archive.Close()
	var gz bytes.Buffer
	g := gzip.NewWriter(&gz)
	_, _ = g.Write([]byte(base64.RawURLEncoding.EncodeToString([]byte("x" + hidden))))
	_ = g.Close()
	for name, data := range map[string][]byte{
		"raw":                        []byte("..." + hidden + "..."),
		"state private, base64 json": state,
		"a plan's embedded state":    zipped.Bytes(),
		"gzip of url base64":         gz.Bytes(),
		"protobuf bytes":             append([]byte{0x0a, byte(len(inner))}, inner...),
	} {
		if found := leaks(name, data, hidden); len(found) == 0 {
			t.Errorf("%s: the value was not found", name)
		}
	}
	if found := leaks("clean", state, "fake-other-value-0123456789"); len(found) != 0 {
		t.Errorf("found what is not there: %v", found)
	}
}

// checkClean fails t when value is in the workspace's state files or the saved plan's records.
func checkClean(t *testing.T, w *workspace, plan string, value string) {
	t.Helper()
	for _, name := range []string{"terraform.tfstate", "terraform.tfstate.backup"} {
		data, err := os.ReadFile(filepath.Join(w.dir, name))
		if err != nil {
			continue
		}
		if found := leaks(name, data, value); len(found) > 0 {
			t.Errorf("%s holds the value: %v", name, found)
		}
	}
	if plan == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(w.dir, plan))
	if err != nil {
		t.Fatal(err)
	}
	has, err := planHas(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range planRecords {
		if !has[record] {
			t.Fatalf("the saved plan has no %s record: the check would read nothing there", record)
		}
	}
	if found := leaks(plan, data, value); len(found) > 0 {
		t.Errorf("the saved plan holds the value: %v", found)
	}
}

// The check catches a provider that keeps a value in its private data: through plan and apply, and only at refresh.
func TestLeakCheckCatchesTheLeakyProvider(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		side := filepath.Join(w.dir, "side")
		for _, mode := range []string{"apply", "refresh"} {
			config := func(revision string) string {
				return strings.Replace(variables, `coffre = { source = "erwinkn/coffre" }`, `leaky = { source = "erwinkn/leaky" }`, 1) +
					"resource \"leaky_secret\" \"s\" {\n  mode = \"" + mode + "\"\n  side_file = \"" + side + "\"\n  revision = \"" + revision + "\"\n  value_wo = var.value\n}\n"
			}
			vars := map[string]string{"TF_VAR_value": hidden}
			w.configure(config("1"))
			w.ok(vars, "apply", "-auto-approve")
			w.configure(config("2"))
			w.ok(vars, "plan", "-out=leak.tfplan")
			data, _ := os.ReadFile(filepath.Join(w.dir, "leak.tfplan"))
			found := strings.Join(leaks("leak.tfplan", data, hidden), " ")
			if mode == "apply" && !strings.Contains(found, "leak.tfplan/tfplan") {
				t.Errorf("%s: the leak in the plan's own record was missed: %q", mode, found)
			}
			if mode == "refresh" {
				// Only the refreshed state the plan carries holds it: a check of tfplan alone, or of the final state, passes.
				if !strings.Contains(found, "leak.tfplan/tfstate") || strings.Contains(found, "leak.tfplan/tfplan") {
					t.Errorf("%s: want the leak in the embedded tfstate alone, found %q", mode, found)
				}
			}
			w.ok(vars, "apply", "leak.tfplan")
			state, _ := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
			if got := leaks("terraform.tfstate", state, hidden); (mode == "apply") != (len(got) > 0) {
				t.Errorf("%s: the final state's leak: %v", mode, got)
			}
			w.ok(vars, "destroy", "-auto-approve")
		}
	})
}
