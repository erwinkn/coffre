// An independent check of W209's tree, proofs, tiles and signed checkpoints,
// with Go's own implementation (golang.org/x/mod/sumdb/tlog and sumdb/note,
// what the Go checksum database's clients run). It shares no code with the
// TypeScript: if both agree, the bytes are RFC 6962/9162's.
//
//   go run . -server http://127.0.0.1:8209 -key 'coffre.example/audit+…' [-count 50]
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

var server string

func get(path string) []byte {
	res, err := http.Get(server + path)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		log.Fatalf("GET %s: %d %s", path, res.StatusCode, body)
	}
	return body
}

type head struct {
	size int64
	root tlog.Hash
	upto string
}

// open checks a checkpoint's signature with note.Open and reads its size and head.
func open(raw []byte, verifiers note.Verifiers) head {
	n, err := note.Open(raw, verifiers)
	if err != nil {
		log.Fatalf("note.Open: %v", err)
	}
	lines := strings.Split(n.Text, "\n")
	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	h, err := tlog.ParseHash(lines[2])
	if err != nil {
		log.Fatal(err)
	}
	return head{size, h, strings.TrimPrefix(lines[3], "upto ")}
}

func hashes(b64 []string) []tlog.Hash {
	out := make([]tlog.Hash, len(b64))
	for i, s := range b64 {
		h, err := tlog.ParseHash(s)
		if err != nil {
			log.Fatal(err)
		}
		out[i] = h
	}
	return out
}

// tiles fetches tiles over HTTP, at the paths Go's tlog names them.
type tiles struct{ fetched int }

func (t *tiles) Height() int { return 8 }
func (t *tiles) ReadTiles(ts []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(ts))
	for i, tile := range ts {
		out[i] = get("/audit/" + tile.Path())
		t.fetched++
	}
	return out, nil
}
func (t *tiles) SaveTiles([]tlog.Tile, [][]byte) {}

func main() {
	flag.StringVar(&server, "server", "http://127.0.0.1:8209", "the proof server")
	key := flag.String("key", "", "the log's note verifier key")
	count := flag.Int("count", 50, "entries to prove")
	flag.Parse()
	v, err := note.NewVerifier(*key)
	if err != nil {
		log.Fatal(err)
	}
	verifiers := note.VerifierList(v)
	top := open(get("/audit/checkpoint"), verifiers)
	fmt.Printf("checkpoint: %d leaves, up to number %s, signature ok\n", top.size, top.upto)

	// The tiles, read by Go's TileHashReader, which checks every tile it loads against the signed head.
	tr := &tiles{}
	reader := tlog.TileHashReader(tlog.Tree{N: top.size, Hash: top.root}, tr)
	th, err := tlog.TreeHash(top.size, reader)
	if err != nil || th != top.root {
		log.Fatalf("tree hash from tiles: %v %v", th, err)
	}
	fmt.Printf("tree hash from the tiles: matches the signed head\n")

	var numbers []string
	json.Unmarshal(get(fmt.Sprintf("/audit/numbers?count=%d", *count)), &numbers)
	bad := 0
	for _, number := range numbers {
		var p struct {
			Index      int64    `json:"index"`
			Size       int64    `json:"size"`
			Leaf       string   `json:"leaf"`
			Proof      []string `json:"proof"`
			Checkpoint string   `json:"checkpoint"`
		}
		json.Unmarshal(get("/audit/proof?number="+number+"&size="+strconv.FormatInt(top.size, 10)), &p)
		h := open([]byte(p.Checkpoint), verifiers)
		leaf, _ := base64.StdEncoding.DecodeString(p.Leaf)
		if !bytes.Contains(leaf, []byte(`"`+number+`"`)) {
			log.Fatalf("leaf of %s does not name its number", number)
		}
		rh := tlog.RecordHash(leaf)
		proof := hashes(p.Proof)
		if err := tlog.CheckRecord(proof, h.size, h.root, p.Index, rh); err != nil {
			fmt.Printf("  %s: CheckRecord: %v\n", number, err)
			bad++
			continue
		}
		// Go's own proof from the same tiles must be the same bytes.
		mine, err := tlog.ProveRecord(h.size, p.Index, reader)
		if err != nil || len(mine) != len(proof) {
			log.Fatalf("ProveRecord %s: %v", number, err)
		}
		for i := range mine {
			if mine[i] != proof[i] {
				log.Fatalf("ProveRecord %s: hash %d differs", number, i)
			}
		}
		// And a proof with one byte flipped must fail.
		proof[0][0] ^= 1
		if tlog.CheckRecord(proof, h.size, h.root, p.Index, rh) == nil {
			log.Fatalf("a corrupted proof of %s passed", number)
		}
	}
	fmt.Printf("inclusion: %d of %d entries proven (CheckRecord), Go's ProveRecord gives the same bytes, corrupted proofs fail\n", len(numbers)-bad, len(numbers))

	// Consistency from older checkpoints to the newest.
	checked := 0
	for _, frac := range []int64{1, 2, 3, 5, 8, 13, 100, 1000} {
		older := open(get(fmt.Sprintf("/audit/checkpoint?size=%d", top.size/frac)), verifiers)
		if older.size == 0 || older.size == top.size {
			continue
		}
		var c struct {
			Proof []string `json:"proof"`
		}
		json.Unmarshal(get(fmt.Sprintf("/audit/consistency?from=%d&to=%d", older.size, top.size)), &c)
		proof := hashes(c.Proof)
		if err := tlog.CheckTree(proof, top.size, top.root, older.size, older.root); err != nil {
			log.Fatalf("CheckTree %d -> %d: %v", older.size, top.size, err)
		}
		mine, err := tlog.ProveTree(top.size, older.size, reader)
		if err != nil || len(mine) != len(proof) {
			log.Fatalf("ProveTree: %v", err)
		}
		for i := range mine {
			if mine[i] != proof[i] {
				log.Fatalf("ProveTree %d -> %d: hash %d differs", older.size, top.size, i)
			}
		}
		checked++
	}
	fmt.Printf("consistency: %d older checkpoints proven prefixes of the newest (CheckTree), Go's ProveTree gives the same bytes\n", checked)
	fmt.Printf("tiles fetched: %d\n", tr.fetched)
	if bad > 0 {
		os.Exit(1)
	}
}
