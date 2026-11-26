package provider

import (
	"context"
	"strings"
	"testing"

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
	for at, ok := range map[string]bool{"prod": true, "my-env_2": true, "": false, "a/b": false, "dev@me": false} {
		var resp validator.StringResponse
		slug{}.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("environment"), ConfigValue: types.StringValue(at)}, &resp)
		if resp.Diagnostics.HasError() == ok {
			t.Errorf("%q: refused %v", at, !ok)
		}
	}
}
