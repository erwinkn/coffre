package coffre

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
)

// Listed is one key of an environment's listing (GET /api/secrets/:project/:environment),
// with only what the provider keeps. A listing gives a plain key's value too: this type
// has no field for it, so it is never decoded.
type Listed struct {
	Key         string  `json:"key"`
	Archived    bool    `json:"archived"`
	Version     *int64  `json:"version"`
	VersionID   *string `json:"versionId"`
	Secret      *string `json:"secret"`
	UpdatedBy   *string `json:"updatedBy"`
	Sensitivity *string `json:"sensitivity"`
	Reference   *struct {
		Source string `json:"source"`
	} `json:"reference"`
	Parent *struct {
		From  string `json:"from"`
		State string `json:"state"`
	} `json:"parent"`
}

// Own says whether the environment holds the key's value itself, live: not
// archived, not passed down by a parent, not a reference.
func (l Listed) Own() bool {
	return !l.Archived && l.Reference == nil && (l.Parent == nil || l.Parent.State == "overridden")
}

// Inherited says whether the key reads what a parent passes down.
func (l Listed) Inherited() bool {
	return !l.Archived && l.Parent != nil && l.Parent.State == "inherited"
}

// Empty says whether the key holds nothing here: archived, dismissed from what a parent passes
// down, or an own row with no value (a reference broken in coffre leaves one). A write that
// replaces nothing makes it again. An inherited key whose version this account cannot see is not
// empty: it holds the parent's value.
func (l Listed) Empty() bool {
	return l.Archived || (l.Parent != nil && l.Parent.State == "removed") || (l.Own() && l.VersionID == nil)
}

// listings remembers each environment's listing for as long as the client
// lives, which is one Terraform operation: a refresh of a hundred keys of one
// environment lists it once. A write there forgets it.
type listings struct {
	mu    sync.Mutex
	known map[string]*listing
}

type listing struct {
	done chan struct{}
	keys map[string]Listed
	err  error
}

func place(project, environment string) string {
	return "/" + url.PathEscape(project) + "/" + url.PathEscape(environment)
}

// Key is one key of an environment, as its listing has it, or nil when the
// environment has no such key. With `fresh`, the environment is listed again.
func (c *Client) Key(ctx context.Context, project, environment, key string, fresh bool) (*Listed, error) {
	keys, err := c.listing(ctx, project, environment, fresh)
	if err != nil {
		return nil, err
	}
	if found, ok := keys[key]; ok {
		return &found, nil
	}
	return nil, nil
}

func (c *Client) listing(ctx context.Context, project, environment string, fresh bool) (map[string]Listed, error) {
	at := place(project, environment)
	c.listed.mu.Lock()
	if c.listed.known == nil {
		c.listed.known = map[string]*listing{}
	}
	entry, ok := c.listed.known[at]
	if !ok || fresh {
		entry = &listing{done: make(chan struct{})}
		c.listed.known[at] = entry
		c.listed.mu.Unlock()
		var answer struct {
			Keys []Listed `json:"keys"`
		}
		entry.err = c.call(ctx, http.MethodGet, "/secrets"+at, nil, &answer)
		if entry.err == nil {
			entry.keys = make(map[string]Listed, len(answer.Keys))
			for _, listed := range answer.Keys {
				entry.keys[listed.Key] = listed
			}
		}
		close(entry.done)
		if entry.err != nil {
			c.forget(at, entry)
		}
		return entry.keys, entry.err
	}
	c.listed.mu.Unlock()
	select {
	case <-entry.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return entry.keys, entry.err
}

// forget drops an environment's listing, if it is still `entry` (any, if nil).
func (c *Client) forget(at string, entry *listing) {
	c.listed.mu.Lock()
	defer c.listed.mu.Unlock()
	if current, ok := c.listed.known[at]; ok && (entry == nil || current == entry) {
		delete(c.listed.known, at)
	}
}

// Replaces is what a write says the key reads now: a version, by its id, or
// nothing at all (`null`: no value and no reference, here or passed down).
type Replaces struct{ VersionID *string }

// Nothing is the Replaces of a key that holds nothing yet.
var Nothing = Replaces{}

// Version is the Replaces of a key that reads that version now.
func Version(id string) Replaces { return Replaces{VersionID: &id} }

// Written is what a write made of the key: its version, by number, and its sensitivity.
type Written struct {
	Version     int64  `json:"version"`
	Sensitivity string `json:"sensitivity"`
}

// Write gives one key a value, of that sensitivity, only over what it
// `replaces` (PATCH /api/secrets/:project/:environment): coffre refuses it,
// 409 `stale`, when the key reads anything else now.
func (c *Client) Write(ctx context.Context, project, environment, key, value, sensitivity string, replaces Replaces) (Written, error) {
	at := place(project, environment)
	defer c.forget(at, nil)
	written := map[string]any{"value": value, "sensitivity": sensitivity, "replaces": nil}
	if replaces.VersionID != nil {
		written["replaces"] = *replaces.VersionID
	}
	var answer struct {
		Keys map[string]Written `json:"keys"`
	}
	if err := c.call(ctx, http.MethodPatch, "/secrets"+at, map[string]any{key: written}, &answer); err != nil {
		return Written{}, err
	}
	made, ok := answer.Keys[key]
	if !ok || made.Version < 1 {
		return Written{}, fmt.Errorf("coffre's answer to the write named no version of %s", key)
	}
	return made, nil
}

// Archive archives one key (PATCH /api/secrets/:project/:environment/:key): coffre
// keeps its history, and it can be brought back. One that is not there is archived already.
func (c *Client) Archive(ctx context.Context, project, environment, key string) error {
	at := place(project, environment)
	defer c.forget(at, nil)
	err := c.call(ctx, http.MethodPatch, "/secrets"+at+"/"+url.PathEscape(key), map[string]any{"archived": true}, nil)
	if Is(err, http.StatusNotFound, "") {
		return nil
	}
	return err
}
