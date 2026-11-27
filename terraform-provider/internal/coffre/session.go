package coffre

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Session signs in with a person's session, the one `coffre login <url>` saved: read once,
// kept in memory, never renewed or written back (the CLI owns its file).
type Session struct {
	Token string
	// Member is who it is, `user:<email>`, as the file says.
	Member string
}

func (s *Session) Bearer(context.Context, *Client) (string, error) { return s.Token, nil }
func (*Session) Renew(string) bool                                 { return false }

// CredentialsFile is the CLI's file of saved sessions under a home directory: ~/.coffre/credentials.json.
func CredentialsFile(home string) string {
	return filepath.Join(home, ".coffre", "credentials.json")
}

// ReadSession is the person's session the CLI saved for `origin` in `file`, or why there is none
// to use. Only a person's is taken: the CLI also saves a service token's and a CI run's, which
// are no person's. Nothing in an error comes from the file but its path and the origin.
func ReadSession(file, origin string, now time.Time) (*Session, error) {
	login := fmt.Sprintf("run `coffre login %s`", origin)
	raw, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no coffre session is saved on this machine (%s): %s first", file, login)
	}
	if err != nil {
		return nil, fmt.Errorf("%s could not be read: %v", file, errors.Unwrap(err))
	}
	var store struct {
		Version   int `json:"version"`
		Instances map[string]struct {
			Mode      string  `json:"mode"`
			Kind      *string `json:"kind"`
			Token     string  `json:"token"`
			ExpiresAt *string `json:"expiresAt"`
			Principal *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"principal"`
		} `json:"instances"`
	}
	if json.Unmarshal(raw, &store) != nil || store.Version != 2 {
		return nil, fmt.Errorf("%s is not a credentials file this provider reads (the CLI's, version 2): %s again", file, login)
	}
	saved, ok := store.Instances[origin]
	switch {
	case !ok:
		return nil, fmt.Errorf("no session is saved for %s in %s: %s", origin, file, login)
	case saved.Kind != nil:
		return nil, fmt.Errorf("the session saved for %s is %s, not a person's: session = true signs in as the person who ran `coffre login %s`; sign a service in with token or oidc", origin, whose(*saved.Kind), origin)
	case saved.Mode != "signin" || saved.Token == "":
		return nil, fmt.Errorf("the session saved for %s is not one coffre 0.16 signs in with: %s", origin, login)
	}
	if saved.ExpiresAt != nil && *saved.ExpiresAt != "" {
		ends, err := time.Parse(time.RFC3339Nano, *saved.ExpiresAt)
		if err == nil && !now.Before(ends) {
			return nil, fmt.Errorf("your session on %s ended on %s: %s", origin, ends.UTC().Format(time.DateOnly), login)
		}
	}
	member := ""
	if saved.Principal != nil && saved.Principal.Type == "user" && saved.Principal.ID != "" {
		member = "user:" + strings.ToLower(saved.Principal.ID)
	}
	return &Session{Token: saved.Token, Member: member}, nil
}

// whose names a saved session's kind, as the CLI saves it.
func whose(kind string) string {
	switch kind {
	case "token":
		return "a service token's"
	case "run":
		return "a CI run's"
	}
	return "0.14's, behind Cloudflare Access,"
}
