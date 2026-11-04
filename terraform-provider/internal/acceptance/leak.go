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
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
)

// Section 7, guarantee 5: a check of the saved plan and the state for a
// value, their private data decoded layer by layer, not only a search of
// their bytes, nor only `terraform show -json`. Provider private data is
// base64 in a state file and raw JSON inside a plan's protobuf, and a
// provider may encode it again itself.
//
// Every layer is read whole: a zip archive's files, a gzip stream, a
// protobuf message's fields, a JSON document's strings (each decoded as
// base64 too, however short), and the base64 runs of any other text. A
// layer the check cannot read in full (too large, nested too deep) fails
// the check: an unread layer never counts as clean.

// base64Run is a run of base64 (either alphabet) in text that is not JSON:
// 4 characters, the shortest that decodes to anything.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{4,}={0,2}`)

const (
	maxDepth = 24       // layers within layers
	maxSize  = 64 << 20 // bytes one zip file or gzip stream may hold
)

var encodings = []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}

// leaks returns where secret appears in data, named from name, or an
// error naming a layer it could not read in full.
func leaks(name string, data []byte, secret string) ([]string, error) {
	s := scan{secret: secret, seen: map[string]bool{}}
	s.search(name, data, 0, true)
	return s.found, s.err
}

type scan struct {
	secret string
	seen   map[string]bool
	found  []string
	err    error
}

// search looks for the secret in data, then in each layer data holds. A
// layer's bytes are tried as protobuf only where proto says they may be
// one: the plan's own record and the fields of a message within it.
func (s *scan) search(where string, data []byte, depth int, proto bool) {
	if s.err != nil || len(data) == 0 {
		return
	}
	key := string(data)
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	if contains(data, s.secret) {
		s.found = append(s.found, where)
		return
	}
	if depth >= maxDepth {
		s.err = fmt.Errorf("%s: nested more than %d layers deep; the check cannot read it all", where, maxDepth)
		return
	}
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			s.err = fmt.Errorf("%s: a zip archive that does not read: %w", where, err)
			return
		}
		for _, file := range archive.File {
			r, err := file.Open()
			if err != nil {
				s.err = fmt.Errorf("%s/%s: %w", where, file.Name, err)
				return
			}
			inner, err := readAll(r)
			_ = r.Close()
			if err != nil {
				s.err = fmt.Errorf("%s/%s: %w", where, file.Name, err)
				return
			}
			s.search(where+"/"+file.Name, inner, depth+1, file.Name == "tfplan")
		}
		return
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		// Bytes whose header does not read are not gzip (no reader would
		// open them), and are searched as bytes below. Once the header
		// reads, the stream is read whole or fails the check: one too
		// large or cut short may hold the value past where reading stopped.
		if r, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			inner, err := readAll(r)
			if err != nil {
				s.err = fmt.Errorf("%s(gzip): %w", where, err)
				return
			}
			s.search(where+"(gzip)", inner, depth+1, false)
			return
		}
	}
	if json.Valid(data) {
		var document any
		_ = json.Unmarshal(data, &document)
		walkStrings(document, func(text string) {
			s.search(where+"(json)", []byte(text), depth+1, false)
			s.decode(where+"(json)", text, depth)
		})
		return
	}
	// Text can parse as a message by chance: it is read as both.
	if proto {
		s.message(where, data, depth)
	}
	if utf8.Valid(data) {
		for _, run := range base64Run.FindAll(data, -1) {
			s.decode(where, string(run), depth)
		}
	}
}

// decode searches what text decodes to, in each base64 alphabet. Bytes that
// are neither text nor an archive are only searched, not decoded again:
// they are what most text decodes to, and hold no further layer.
func (s *scan) decode(where, text string, depth int) {
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(text)
		if err != nil || len(decoded) == 0 {
			continue
		}
		if utf8.Valid(decoded) || bytes.HasPrefix(decoded, []byte("PK\x03\x04")) || bytes.HasPrefix(decoded, []byte{0x1f, 0x8b}) {
			s.search(where+"(base64)", decoded, depth+1, false)
		} else if contains(decoded, s.secret) {
			s.found = append(s.found, where+"(base64)")
		}
	}
}

// message searches each length-delimited field of data as a protobuf
// message, when data parses as one to its end.
func (s *scan) message(where string, data []byte, depth int) {
	var fields [][]byte
	for rest := data; len(rest) > 0; {
		number, kind, n := protowire.ConsumeTag(rest)
		if n < 0 || number <= 0 {
			return
		}
		rest = rest[n:]
		if kind == protowire.BytesType {
			field, m := protowire.ConsumeBytes(rest)
			if m < 0 {
				return
			}
			fields = append(fields, field)
			rest = rest[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(number, kind, rest)
		if m < 0 {
			return
		}
		rest = rest[m:]
	}
	for _, field := range fields {
		s.search(where+"(proto)", field, depth+1, true)
	}
}

// readAll reads r to its end, or fails past maxSize.
func readAll(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err == nil && len(data) > maxSize {
		err = fmt.Errorf("larger than %d bytes; the check cannot read it all", maxSize)
	}
	return data, err
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
