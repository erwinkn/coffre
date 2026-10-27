// An independent check of coffre's audit trees (packages/core/src/audit) with
// Go's own implementation: golang.org/x/mod/sumdb/tlog and sumdb/note, what
// the Go checksum database's clients run. It shares no code with the
// TypeScript, so where both agree the bytes are RFC 9162's and C2SP's.
//
//	go run . vectors > ../vectors/audit-tree-go.json   the tree Go builds, for the TypeScript tests
//	go run . check <fixture.json>                       a split log written by fixture.ts, checked
//
// scripts/audit-tree-go.sh runs both.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const height = 8

// A tree held as its stored hashes, the way Go's sumdb server keeps one.
type stored []tlog.Hash

func (s stored) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x >= int64(len(s)) {
			return nil, fmt.Errorf("no stored hash %d", x)
		}
		out[i] = s[x]
	}
	return out, nil
}

// build stores every leaf hash as tlog.StoredHashesForRecordHash does, record by record.
func build(leaves []tlog.Hash) stored {
	var s stored
	for n, leaf := range leaves {
		hs, err := tlog.StoredHashesForRecordHash(int64(n), leaf, s)
		if err != nil {
			log.Fatal(err)
		}
		s = append(s, hs...)
	}
	return s
}

func b64(hs []tlog.Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = base64.StdEncoding.EncodeToString(h[:])
	}
	return out
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

// vectors: the tree of leaves RecordHash("entry i"), as Go builds it: heads, proofs and every tile's digest.
func vectors() {
	sizes := []int64{1, 2, 3, 7, 8, 255, 256, 257, 511, 512, 600, 65535, 65536, 65537, 70001}
	max := sizes[len(sizes)-1]
	leaves := make([]tlog.Hash, max)
	for i := range leaves {
		leaves[i] = tlog.RecordHash([]byte(fmt.Sprintf("entry %d", i)))
	}
	s := build(leaves)
	type inclusion struct {
		Index int64    `json:"index"`
		Size  int64    `json:"size"`
		Proof []string `json:"proof"`
	}
	out := struct {
		Sizes       []int64           `json:"sizes"`
		Heads       map[string]string `json:"heads"`
		Inclusion   []inclusion       `json:"inclusion"`
		Consistency []consistency     `json:"consistency"`
		Tiles       map[string]string `json:"tiles"`
	}{Sizes: sizes, Heads: map[string]string{}, Tiles: map[string]string{}}
	for _, n := range sizes {
		h := must(tlog.TreeHash(n, s))
		out.Heads[strconv.FormatInt(n, 10)] = base64.StdEncoding.EncodeToString(h[:])
		for _, m := range []int64{0, n / 3, n - 1} {
			out.Inclusion = append(out.Inclusion, inclusion{Index: m, Size: n, Proof: b64(must(tlog.ProveRecord(n, m, s)))})
		}
		for _, m := range []int64{1, n / 2, n - 1} {
			if m > 0 && m < n {
				out.Consistency = append(out.Consistency, consistency{From: m, To: n, Proof: b64(must(tlog.ProveTree(n, m, s)))})
			}
		}
	}
	for _, t := range tlog.NewTiles(height, 0, max) {
		data := must(tlog.ReadTileData(t, s))
		sum := sha256.Sum256(data)
		out.Tiles[t.Path()] = hex.EncodeToString(sum[:])
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(0, enc.Encode(out))
}

// The fixture fixture.ts writes: a split log's pairs, and each tree's tiles, sampled proofs and cuts.
type record struct {
	Index int64    `json:"index"`
	Size  int64    `json:"size"`
	Data  string   `json:"data"`
	Proof []string `json:"proof"`
}
type consistency struct {
	From  int64    `json:"from"`
	To    int64    `json:"to"`
	Proof []string `json:"proof"`
}
type cut struct {
	Cut         int64         `json:"cut"`
	Kept        []string      `json:"kept"`
	Records     []record      `json:"records"`
	Consistency []consistency `json:"consistency"`
}
type tree struct {
	Tiles       map[string]string `json:"tiles"`
	Records     []record          `json:"records"`
	Consistency []consistency     `json:"consistency"`
	Cuts        []cut             `json:"cuts"`
}
type fixture struct {
	Keys  map[string]string   `json:"keys"`
	Pairs []map[string]string `json:"pairs"`
	Trees map[string]tree     `json:"trees"`
}

// tiles serves tiles from what the TypeScript stored, keyed "level/index": a partial width is a prefix of the newest.
type tiles struct {
	stored map[string][]byte
	read   int
}

func (t *tiles) Height() int { return height }
func (t *tiles) ReadTiles(ts []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(ts))
	for i, tile := range ts {
		data, ok := t.stored[fmt.Sprintf("%d/%d", tile.L, tile.N)]
		if !ok || len(data) < tile.W*tlog.HashSize {
			return nil, fmt.Errorf("no tile %s", tile.Path())
		}
		out[i] = data[:tile.W*tlog.HashSize]
		t.read++
	}
	return out, nil
}
func (t *tiles) SaveTiles([]tlog.Tile, [][]byte) {}

type head struct {
	origin   string
	size     int64
	root     tlog.Hash
	upto, at string
}

func open(raw string, verifiers note.Verifiers) head {
	n := must(note.Open([]byte(raw), verifiers))
	lines := strings.Split(n.Text, "\n")
	if len(lines) != 6 || !strings.HasPrefix(lines[3], "upto ") || !strings.HasPrefix(lines[4], "at ") {
		log.Fatalf("not a coffre checkpoint: %q", n.Text)
	}
	if len(n.Sigs) != 1 || n.Sigs[0].Name != lines[0] {
		log.Fatalf("checkpoint for %s signed by %v", lines[0], n.Sigs)
	}
	return head{lines[0], must(strconv.ParseInt(lines[1], 10, 64)), must(tlog.ParseHash(lines[2])), lines[3][5:], lines[4][3:]}
}

func hashes(b []string) []tlog.Hash {
	out := make([]tlog.Hash, len(b))
	for i, s := range b {
		out[i] = must(tlog.ParseHash(s))
	}
	return out
}

func same(a, b []tlog.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func check(path string) {
	var f fixture
	must(0, json.Unmarshal(must(os.ReadFile(path)), &f))
	names := []string{"changes", "uses"}
	var vs []note.Verifier
	for _, name := range names {
		vs = append(vs, must(note.NewVerifier(f.Keys[name])))
	}
	verifiers := note.VerifierList(vs...)

	// Every pair: each note opens under its own tree's key and origin, and both share upto and at.
	heads := map[string][]head{}
	for i, p := range f.Pairs {
		c, u := open(p["changes"], verifiers), open(p["uses"], verifiers)
		if c.upto != u.upto || c.at != u.at || !strings.HasSuffix(c.origin, "/changes") || !strings.HasSuffix(u.origin, "/uses") {
			log.Fatalf("pair %d is not one pair: %+v %+v", i, c, u)
		}
		// Swapped or crossed, a note fails: each key signs its own origin only.
		if _, err := note.Open([]byte(strings.Replace(p["uses"], u.origin+"\n", c.origin+"\n", 1)), verifiers); err == nil {
			log.Fatalf("pair %d: a uses note renamed to the changes origin opened", i)
		}
		heads["changes"] = append(heads["changes"], c)
		heads["uses"] = append(heads["uses"], u)
	}
	fmt.Printf("pairs: %d, every note opened by note.Open under its own origin's key, every pair at one upto and at\n", len(f.Pairs))

	for _, name := range names {
		t := f.Trees[name]
		hs := heads[name]
		top := hs[len(hs)-1]
		stored := map[string][]byte{}
		for k, v := range t.Tiles {
			stored[k] = must(base64.StdEncoding.DecodeString(v))
		}
		tr := &tiles{stored: stored}
		reader := tlog.TileHashReader(tlog.Tree{N: top.size, Hash: top.root}, tr)
		if th := must(tlog.TreeHash(top.size, reader)); th != top.root {
			log.Fatalf("%s: the tiles do not give the signed head", name)
		}

		// Byte equality: Go rebuilds every tile from the leaf hashes and must get ours, and ours must hold nothing more.
		leaves := make([]tlog.Hash, top.size)
		for i := range leaves {
			tile := stored[fmt.Sprintf("0/%d", i/256)]
			copy(leaves[i][:], tile[(i%256)*tlog.HashSize:])
		}
		s := build(leaves)
		produced := map[string]bool{}
		for _, tile := range tlog.NewTiles(height, 0, top.size) {
			key := fmt.Sprintf("%d/%d", tile.L, tile.N)
			produced[key] = true
			if !bytes.Equal(must(tlog.ReadTileData(tile, s)), stored[key]) {
				log.Fatalf("%s: tile %s differs from Go's", name, tile.Path())
			}
		}
		if len(produced) != len(stored) {
			log.Fatalf("%s: %d tiles stored, Go makes %d", name, len(stored), len(produced))
		}

		// Every head of the tree, a prefix of the newest: Go's ProveTree and ours agree, and CheckTree accepts.
		checked := 0
		for _, h := range hs {
			// Genesis and the newest head have nothing to prove.
			if h.size == 0 || h.size == top.size {
				continue
			}
			checked++
			p := must(tlog.ProveTree(top.size, h.size, reader))
			if err := tlog.CheckTree(p, top.size, top.root, h.size, h.root); err != nil {
				log.Fatalf("%s: CheckTree %d to %d: %v", name, h.size, top.size, err)
			}
		}
		for _, c := range t.Consistency {
			theirs := hashes(c.Proof)
			if !same(theirs, must(tlog.ProveTree(c.To, c.From, reader))) {
				log.Fatalf("%s: consistency %d to %d differs from Go's", name, c.From, c.To)
			}
		}
		// Sampled entries: the leaf is RecordHash of its data, our proof passes CheckRecord, Go proves the same bytes,
		// and a proof with one byte flipped fails.
		for _, r := range t.Records {
			data := must(base64.StdEncoding.DecodeString(r.Data))
			rh := tlog.RecordHash(data)
			if !bytes.Equal(rh[:], leaves[r.Index][:]) {
				log.Fatalf("%s: leaf %d is not RecordHash of its entry", name, r.Index)
			}
			p := hashes(r.Proof)
			if err := tlog.CheckRecord(p, top.size, top.root, r.Index, rh); err != nil {
				log.Fatalf("%s: CheckRecord %d: %v", name, r.Index, err)
			}
			if !same(p, must(tlog.ProveRecord(top.size, r.Index, reader))) {
				log.Fatalf("%s: inclusion %d differs from Go's", name, r.Index)
			}
			if len(p) > 0 {
				p[0][0] ^= 1
				if tlog.CheckRecord(p, top.size, top.root, r.Index, rh) == nil {
					log.Fatalf("%s: a corrupted proof of %d passed", name, r.Index)
				}
			}
		}
		fmt.Printf("%s: %d leaves, %d heads; tiles byte-equal to Go's (%d), TreeHash from TileHashReader matches; %d inclusion and %d consistency proofs equal to Go's; %d heads CheckTree'd (every head but the empty ones and the newest)\n",
			name, top.size, len(hs), len(stored), len(t.Records), len(t.Consistency), checked)

		// Retention cuts: only the tiles that reach past the cut stay. Go's TileHashReader, which checks each tile it
		// loads against the signed head, must still prove every sampled leaf above the cut and every size above it.
		for _, c := range t.Cuts {
			kept := map[string][]byte{}
			for _, k := range c.Kept {
				kept[k] = stored[k]
			}
			ct := &tiles{stored: kept}
			cr := tlog.TileHashReader(tlog.Tree{N: top.size, Hash: top.root}, ct)
			if th := must(tlog.TreeHash(top.size, cr)); th != top.root {
				log.Fatalf("%s cut %d: the head", name, c.Cut)
			}
			for _, r := range c.Records {
				p, err := tlog.ProveRecord(top.size, r.Index, cr)
				if err != nil || !same(p, hashes(r.Proof)) {
					log.Fatalf("%s cut %d: inclusion %d: %v", name, c.Cut, r.Index, err)
				}
				if err := tlog.CheckRecord(p, top.size, top.root, r.Index, leaves[r.Index]); err != nil {
					log.Fatalf("%s cut %d: CheckRecord %d: %v", name, c.Cut, r.Index, err)
				}
			}
			for _, k := range c.Consistency {
				p, err := tlog.ProveTree(k.To, k.From, cr)
				if err != nil || !same(p, hashes(k.Proof)) {
					log.Fatalf("%s cut %d: consistency %d to %d: %v", name, c.Cut, k.From, k.To, err)
				}
			}
			// Below the cut, leaves are gone: proving the first one must fail for want of its tile.
			if c.Cut > 256 {
				if _, err := tlog.ProveRecord(top.size, 0, cr); err == nil {
					log.Fatalf("%s cut %d: leaf 0 still provable", name, c.Cut)
				}
			}
			fmt.Printf("%s cut at %d: %d of %d tiles kept; %d inclusion and %d consistency proofs above it equal to Go's through TileHashReader; leaf 0 unprovable\n",
				name, c.Cut, len(kept), len(stored), len(c.Records), len(c.Consistency))
		}
	}
}

func main() {
	log.SetFlags(0)
	if len(os.Args) == 2 && os.Args[1] == "vectors" {
		vectors()
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "check" {
		check(os.Args[2])
		fmt.Println("ok")
		return
	}
	keys := []string{"vectors", "check <fixture.json>"}
	sort.Strings(keys)
	log.Fatalf("usage: go run . %s", strings.Join(keys, " | "))
}
