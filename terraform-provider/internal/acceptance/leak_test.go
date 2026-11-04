package acceptance

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
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
		if found, err := leaks(name, data, hidden); err != nil || len(found) == 0 {
			t.Errorf("%s: the value was not found (%v)", name, err)
		}
	}
	if found, err := leaks("clean", state, "fake-other-value-0123456789"); err != nil || len(found) != 0 {
		t.Errorf("found what is not there: %v (%v)", found, err)
	}
}

// A value is found however short, and however much comes before it; a layer the check cannot read fails it.
func TestLeakCheckReadsEverything(t *testing.T) {
	const short = "p$7"
	private := func(value string) []byte {
		inner, _ := json.Marshal(map[string]string{"hidden": base64.StdEncoding.EncodeToString([]byte(value))})
		state, _ := json.Marshal(map[string]any{"resources": []any{map[string]any{"instances": []any{map[string]any{"private": base64.StdEncoding.EncodeToString(inner)}}}}})
		return state
	}
	if found, err := leaks("short", private(short), short); err != nil || len(found) == 0 {
		t.Errorf("a short value was not found: %v (%v)", found, err)
	}
	if found, err := leaks("short, clean", private("q%8"), short); err != nil || len(found) != 0 {
		t.Errorf("found a short value that is not there: %v (%v)", found, err)
	}
	// A plan record: protobuf, its private data raw JSON in a field after thousands of other base64-like runs.
	var record []byte
	for i := 0; i < 5000; i++ {
		record = protowire.AppendTag(record, 1, protowire.BytesType)
		record = protowire.AppendBytes(record, []byte(fmt.Sprintf("coffre_secret.s%04d", i)))
	}
	inner, _ := json.Marshal(map[string]string{"hidden": base64.StdEncoding.EncodeToString([]byte(short))})
	record = protowire.AppendTag(record, 6, protowire.BytesType)
	record = protowire.AppendBytes(record, inner)
	if found, err := leaks("late", record, short); err != nil || len(found) == 0 {
		t.Errorf("a value after 5000 runs was not found: %v (%v)", found, err)
	}
	// Too deep to read: an error, never clean.
	deep := []byte("fake-other")
	for i := 0; i < maxDepth+2; i++ {
		deep, _ = json.Marshal(base64.StdEncoding.EncodeToString(deep))
	}
	if found, err := leaks("deep", deep, short); err == nil {
		t.Errorf("a layer past the depth limit counted as clean: %v", found)
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
		if found, err := leaks(name, data, value); err != nil || len(found) > 0 {
			t.Errorf("%s holds the value: %v (%v)", name, found, err)
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
	if found, err := leaks(plan, data, value); err != nil || len(found) > 0 {
		t.Errorf("the saved plan holds the value: %v (%v)", found, err)
	}
}

// The check catches a provider that keeps a value in its private data: through plan and apply, and only at refresh,
// a long value and a short one.
func TestLeakCheckCatchesTheLeakyProvider(t *testing.T) {
	eachCLI(t, func(t *testing.T, w *workspace) {
		side := filepath.Join(w.dir, "side")
		for _, run := range []struct{ mode, secret string }{{"apply", hidden}, {"refresh", hidden}, {"apply", "p$7"}, {"refresh", "p$7"}} {
			mode, secret := run.mode, run.secret
			config := func(revision string) string {
				return strings.Replace(variables, `coffre = { source = "erwinkn/coffre" }`, `leaky = { source = "erwinkn/leaky" }`, 1) +
					"resource \"leaky_secret\" \"s\" {\n  mode = \"" + mode + "\"\n  side_file = \"" + side + "\"\n  revision = \"" + revision + "\"\n  value_wo = var.value\n}\n"
			}
			vars := map[string]string{"TF_VAR_value": secret}
			w.configure(config("1"))
			w.ok(vars, "apply", "-auto-approve")
			w.configure(config("2"))
			w.ok(vars, "plan", "-out=leak.tfplan")
			data, _ := os.ReadFile(filepath.Join(w.dir, "leak.tfplan"))
			all, err := leaks("leak.tfplan", data, secret)
			if err != nil {
				t.Fatal(err)
			}
			found := strings.Join(all, " ")
			if mode == "apply" && !strings.Contains(found, "leak.tfplan/tfplan") {
				t.Errorf("%s, %q: the leak in the plan's own record was missed: %q", mode, secret, found)
			}
			if mode == "refresh" {
				// Only the refreshed state the plan carries holds it: a check of tfplan alone, or of the final state, passes.
				if !strings.Contains(found, "leak.tfplan/tfstate") || strings.Contains(found, "leak.tfplan/tfplan") {
					t.Errorf("%s, %q: want the leak in the embedded tfstate alone, found %q", mode, secret, found)
				}
			}
			w.ok(vars, "apply", "leak.tfplan")
			state, _ := os.ReadFile(filepath.Join(w.dir, "terraform.tfstate"))
			if got, err := leaks("terraform.tfstate", state, secret); err != nil || (mode == "apply") != (len(got) > 0) {
				t.Errorf("%s, %q: the final state's leak: %v", mode, secret, got)
			}
			w.ok(vars, "destroy", "-auto-approve")
		}
	})
}
