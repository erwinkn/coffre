package acceptance

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// Section 7, guarantee 5: a check of the saved plan and the state for a
// value, their private data decoded layer by layer, not only a search of
// their bytes, nor only `terraform show -json`. Provider private data is
// base64 in a state file and raw JSON inside a plan's protobuf, and a
// provider may encode it again itself.

// base64Run is a run of base64 (either alphabet) long enough to hold a value.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{12,}={0,2}`)

const maxDepth = 6

// leaks returns where secret appears in data, named from name: in its
// bytes, in a zip archive's files, a gzip stream, a JSON document's
// strings, and anything base64 decodes to, each searched again.
func leaks(name string, data []byte, secret string) []string {
	var found []string
	seen := map[string]bool{}
	var search func(where string, data []byte, depth int)
	search = func(where string, data []byte, depth int) {
		if depth > maxDepth || len(data) == 0 {
			return
		}
		key := string(data)
		if seen[key] {
			return
		}
		seen[key] = true
		if contains(data, secret) {
			found = append(found, where)
			return
		}
		if archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
			for _, file := range archive.File {
				if r, err := file.Open(); err == nil {
					inner, _ := io.ReadAll(io.LimitReader(r, 64<<20))
					_ = r.Close()
					search(where+"/"+file.Name, inner, depth+1)
				}
			}
			return
		}
		if r, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			if inner, err := io.ReadAll(io.LimitReader(r, 64<<20)); err == nil {
				search(where+"(gzip)", inner, depth+1)
			}
		}
		var document any
		if json.Unmarshal(data, &document) == nil {
			walkStrings(document, func(s string) { search(where+"(json)", []byte(s), depth+1) })
		}
		for _, run := range base64Run.FindAll(data, 4096) {
			for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if decoded, err := encoding.DecodeString(string(run)); err == nil {
					search(where+"(base64)", decoded, depth+1)
				}
			}
		}
	}
	search(name, data, 0)
	return found
}

// contains reports whether data holds secret as it is or JSON-escaped.
func contains(data []byte, secret string) bool {
	if bytes.Contains(data, []byte(secret)) {
		return true
	}
	escaped, _ := json.Marshal(secret)
	return bytes.Contains(data, escaped[1:len(escaped)-1])
}

func walkStrings(value any, visit func(string)) {
	switch v := value.(type) {
	case string:
		visit(v)
	case []any:
		for _, item := range v {
			walkStrings(item, visit)
		}
	case map[string]any:
		for key, item := range v {
			visit(key)
			walkStrings(item, visit)
		}
	}
}

// planRecords are the saved plan file's records the check must read: the
// plan itself and the two state snapshots it carries.
var planRecords = []string{"tfplan", "tfstate", "tfstate-prev"}

// planHas reports which of a saved plan's records exist, so that a check
// of "every record" cannot pass on a plan file it misread.
func planHas(data []byte) (map[string]bool, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("a saved plan is a zip archive: %w", err)
	}
	has := map[string]bool{}
	for _, file := range archive.File {
		has[file.Name] = true
	}
	return has, nil
}
