package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/erwinkn/coffre/terraform-provider/internal/coffre"
)

func ptr[T any](v T) *T { return &v }

func TestOurs(t *testing.T) {
	mine := coffre.Listed{Key: "K", Version: ptr(int64(7)), VersionID: ptr("v7"), Secret: ptr("row-1")}
	with := func(change func(*coffre.Listed)) *coffre.Listed {
		l := mine
		change(&l)
		return &l
	}
	for _, test := range []struct {
		name    string
		written *written
		listed  *coffre.Listed
		ours    bool
	}{
		{"what it wrote", &written{Version: 7, Secret: "row-1"}, &mine, true},
		{"what it wrote, its row not yet known", &written{Version: 7}, &mine, true},
		{"written since", &written{Version: 7, Secret: "row-1"}, with(func(l *coffre.Listed) { l.Version = ptr(int64(8)) }), false},
		{"another key renamed onto its name", &written{Version: 7, Secret: "row-1"}, with(func(l *coffre.Listed) { l.Secret = ptr("row-2") }), false},
		{"made a reference", &written{Version: 7, Secret: "row-1"}, with(func(l *coffre.Listed) {
			l.Reference = &struct {
				Source string `json:"source"`
			}{"tf/prod/A"}
		}), false},
		{"reset to what a parent passes down", &written{Version: 7, Secret: "row-1"}, with(func(l *coffre.Listed) {
			l.Parent = &struct {
				From  string `json:"from"`
				State string `json:"state"`
			}{"prod", "inherited"}
		}), false},
		{"never written: imported", nil, &mine, false},
		{"no version seen", &written{Version: 7}, with(func(l *coffre.Listed) { l.Version = nil }), false},
	} {
		if got := ours(test.written, test.listed); got != test.ours {
			t.Errorf("%s: ours = %v", test.name, got)
		}
	}
}

func TestValueRefusalSaysNothingOfIt(t *testing.T) {
	canary := "canary-" + strings.Repeat("x", 70_000)
	for _, text := range []string{canary, "canary\x00nul"} {
		var resp validator.StringResponse
		value{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("value_wo"), ConfigValue: types.StringValue(text)}, &resp)
		if !resp.Diagnostics.HasError() {
			t.Fatalf("%d bytes were not refused", len(text))
		}
		for _, d := range resp.Diagnostics {
			if strings.Contains(d.Summary()+d.Detail(), "canary") {
				t.Errorf("the refusal says the value: %s", d.Detail())
			}
		}
	}
	// 64 KiB in UTF-16 code units, as coffre counts them: 32,768 characters outside the BMP are 65,536.
	for text, ok := range map[string]bool{strings.Repeat("a", 65_536): true, strings.Repeat("a", 65_537): false, strings.Repeat("😀", 32_768): true, strings.Repeat("😀", 32_769): false, "": true} {
		var resp validator.StringResponse
		value{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("value_wo"), ConfigValue: types.StringValue(text)}, &resp)
		if resp.Diagnostics.HasError() == ok {
			t.Errorf("%d bytes: refused %v", len(text), !ok)
		}
	}
}

func TestSlug(t *testing.T) {
	for at, ok := range map[string]bool{"prod": true, "my-env-2": true, "0": true, "": false, "a/b": false, "dev@me": false, "..": false, "Prod": false, "my_env": false, "-prod": false, strings.Repeat("a", 64): false} {
		var resp validator.StringResponse
		slug{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("environment"), ConfigValue: types.StringValue(at)}, &resp)
		if resp.Diagnostics.HasError() == ok {
			t.Errorf("%q: refused %v", at, !ok)
		}
	}
}

// recorded keeps what settle sets, of the state and the private state.
type recorded struct {
	model   *secretModel
	written []byte
}

func (r *recorded) Set(_ context.Context, m any) diag.Diagnostics {
	r.model = m.(*secretModel)
	return nil
}

func (r *recorded) SetKey(_ context.Context, _ string, raw []byte) diag.Diagnostics {
	r.written = raw
	return nil
}

// settle records version 7, as the write answered it, and whatever the key lists after.
func TestSettle(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		listing   string
		version   int64
		versionID string
		written   written
		warned    bool
	}{
		{"listed as written", 200, `{"keys":[{"key":"K","version":7,"versionId":"v7","secret":"row-1","updatedBy":"token:terraform","sensitivity":"secret"}]}`,
			7, "v7", written{Version: 7, Secret: "row-1"}, false},
		{"written again in between", 200, `{"keys":[{"key":"K","version":8,"versionId":"v8","secret":"row-1","updatedBy":"user:ada@acme.example","sensitivity":"secret"}]}`,
			8, "v8", written{Version: 7, Secret: "row-1", Drift: true}, false},
		{"archived in between", 200, `{"keys":[{"key":"K","archived":true,"version":7,"versionId":"v7","secret":"row-1","sensitivity":"secret"}]}`,
			7, "", written{Version: 7, Drift: true}, false},
		{"not listed after", 403, `{"error":"no_access","message":"no access"}`,
			7, "", written{Version: 7}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(test.status)
				w.Write([]byte(test.listing))
			}))
			t.Cleanup(server.Close)
			r := &secretResource{client: coffre.New(server.URL, coffre.Token("coffre_svc_test"), "test")}
			m := &secretModel{Project: types.StringValue("tf"), Environment: types.StringValue("prod"), Key: types.StringValue("K"),
				ValueWO: types.StringValue("the value"), Sensitivity: types.StringValue("secret")}
			var got recorded
			var diags diag.Diagnostics
			r.settle(context.Background(), m, coffre.Written{Version: 7, Sensitivity: "secret"}, &got, &got, &diags)
			if diags.HasError() || (diags.WarningsCount() > 0) != test.warned {
				t.Fatalf("diagnostics: %v", diags)
			}
			var w written
			if err := json.Unmarshal(got.written, &w); err != nil || w != test.written {
				t.Errorf("private state %s, not %+v", got.written, test.written)
			}
			if got.model.Version.ValueInt64() != test.version || got.model.VersionID.ValueString() != test.versionID ||
				!got.model.ValueWO.IsNull() || got.model.Sensitivity.ValueString() != "secret" || got.model.ID.ValueString() != "tf/prod/K" {
				t.Errorf("state %+v", got.model)
			}
		})
	}
}
