// Package coffre is the provider's client of coffre's HTTP API: the four
// calls docs/design/terraform-provider.md (section 3) names, and the
// sign-in that comes before them. It never asks for a value, and drops
// the plain values a list carries.
package coffre

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Auth is how the provider signs in: exactly one of Token, Service alone
// (GitHub Actions' ID token, fetched from the runner), or Service with
// IDToken (any issuer's, one per Terraform phase).
type Auth struct {
	Token   string
	Service string
	IDToken string
}

// Runner reads the CI platform's own variables (GitHub's
// ACTIONS_ID_TOKEN_REQUEST_URL and _TOKEN), as the CLI does; never one of
// the provider's own.
type Runner func(name string) string

// SpentIDToken is the error an apply phase gets when its plan phase spent
// the ID token it was given.
const SpentIDToken = "this ID token was spent by the plan phase of this run; plan with -out and apply the saved plan with a fresh token"

// Client calls one coffre instance. It is safe for concurrent use:
// Terraform applies resources in parallel.
type Client struct {
	origin string
	http   *http.Client
	auth   Auth
	runner Runner
	agent  string

	mu         sync.Mutex
	credential string // the credential an exchange gave, while it serves
	spent      bool   // whether IDToken was traded already, by this process
}

// New returns a client of the instance at origin (scheme://host[:port]).
func New(origin string, auth Auth, runner Runner, httpClient *http.Client, version string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	// A redirect is answered, never followed: on a 307 or 308, Go would send
	// the write's body, its value, again to a URL nobody configured.
	own := *httpClient
	own.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	httpClient = &own
	if runner == nil {
		runner = func(string) string { return "" }
	}
	return &Client{origin: strings.TrimRight(origin, "/"), http: httpClient, auth: auth, runner: runner, agent: "terraform-provider-coffre/" + version}
}

// Origin is the instance's origin, the audience an ID token names.
func (c *Client) Origin() string { return c.origin }

// Error is coffre's refusal: its status, code, reason and message.
type Error struct {
	Status  int
	Code    string
	Reason  string
	Message string
}

func (e *Error) Error() string {
	reason := ""
	if e.Reason != "" {
		reason = " (" + e.Reason + ")"
	}
	return fmt.Sprintf("coffre answered %d %s%s: %s", e.Status, e.Code, reason, e.Message)
}

// IsStatus reports whether err is coffre's refusal with that status and,
// when reason is not empty, that reason.
func IsStatus(err error, status int, reason string) bool {
	var refusal *Error
	return errors.As(err, &refusal) && refusal.Status == status && (reason == "" || refusal.Reason == reason)
}

// Parent is what a fork's key says of its parent's (`parent` in the list).
type Parent struct {
	State string `json:"state"` // inherited, overridden or removed
	From  string `json:"from"`
}

// Key is one key of a list, with only what the provider keeps: never its
// value, which a plain key's listing carries and json drops here.
type Key struct {
	Key         string          `json:"key"`
	Archived    bool            `json:"archived"`
	Version     *int64          `json:"version"`
	VersionID   *string         `json:"versionId"`
	UpdatedBy   *string         `json:"updatedBy"`
	Sensitivity *string         `json:"sensitivity"`
	Reference   json.RawMessage `json:"reference"`
	Parent      *Parent         `json:"parent"`
}

// IsReference reports whether the key is a reference to another's value.
func (k *Key) IsReference() bool {
	return len(k.Reference) > 0 && string(k.Reference) != "null"
}

// Listing is an environment's keys, as `GET /api/secrets/:project/:environment` gives them.
type Listing struct {
	Keys    []Key    `json:"keys"`
	Parents []string `json:"parents"`
}

// Find returns the key named name, or nil.
func (l *Listing) Find(name string) *Key {
	for i := range l.Keys {
		if l.Keys[i].Key == name {
			return &l.Keys[i]
		}
	}
	return nil
}

// Write is one key of a `PATCH /api/secrets/:project/:environment`: a
// value at a nature, or with Value nil a mark of the current one.
// Replaces, when set, is the version the write was planned over.
type Write struct {
	Value       *string
	Sensitivity string
	Replaces    *string
}

// MarshalJSON writes the key's patch, its value included: the one place
// a value leaves the provider.
func (w Write) MarshalJSON() ([]byte, error) {
	body := map[string]string{"sensitivity": w.Sensitivity}
	if w.Value != nil {
		body["value"] = *w.Value
	}
	if w.Replaces != nil {
		body["replaces"] = *w.Replaces
	}
	return json.Marshal(body)
}

// Outcome is what a write made: the key's new version, or the one a mark
// kept, by number and id, and its nature.
type Outcome struct {
	Version     int64  `json:"version"`
	VersionID   string `json:"versionId"`
	Sensitivity string `json:"sensitivity"`
}

func secretsPath(project, environment string, key ...string) string {
	parts := []string{"secrets", url.PathEscape(project), url.PathEscape(environment)}
	for _, k := range key {
		parts = append(parts, url.PathEscape(k))
	}
	return "/api/" + strings.Join(parts, "/")
}

// List lists an environment's keys.
func (c *Client) List(ctx context.Context, project, environment string) (*Listing, error) {
	var listing Listing
	if err := c.call(ctx, http.MethodGet, secretsPath(project, environment), nil, &listing); err != nil {
		return nil, err
	}
	return &listing, nil
}

// Set writes one key and returns what it made.
func (c *Client) Set(ctx context.Context, project, environment, key string, write Write) (*Outcome, error) {
	var answer struct {
		Keys map[string]json.RawMessage `json:"keys"`
	}
	if err := c.call(ctx, http.MethodPatch, secretsPath(project, environment), map[string]Write{key: write}, &answer); err != nil {
		return nil, err
	}
	raw, ok := answer.Keys[key]
	if !ok {
		return nil, fmt.Errorf("coffre's answer names no outcome for %s", key)
	}
	var outcome Outcome
	if err := json.Unmarshal(raw, &outcome); err != nil {
		return nil, fmt.Errorf("coffre's outcome for %s does not read: %w", key, err)
	}
	if outcome.VersionID == "" {
		return nil, fmt.Errorf("%s answered no versionId for %s: the provider needs a coffre that names the version a write made (0.16 or later)", c.origin, key)
	}
	return &outcome, nil
}

// Archive archives one key, which keeps its versions.
func (c *Client) Archive(ctx context.Context, project, environment, key string) error {
	return c.call(ctx, http.MethodPatch, secretsPath(project, environment, key), map[string]bool{"archived": true}, nil)
}

// call makes one request with the current credential: once more, with a
// fresh one, when an exchanged credential expired (401), and again after
// coffre's Retry-After when it asks to be asked again.
func (c *Client) call(ctx context.Context, method, path string, body, into any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	renewed := false
	for attempt := 0; ; attempt++ {
		credential, err := c.bearer(ctx)
		if err != nil {
			return err
		}
		status, header, answer, err := c.send(ctx, method, path, credential, payload)
		if err != nil {
			return err
		}
		if status >= 300 && status < 400 {
			return fmt.Errorf("%s %s%s answered %d, a redirect to %q, which the provider does not follow: set url to the origin coffre answers on", method, c.origin, path, status, header.Get("location"))
		}
		if status >= 200 && status < 300 {
			if into == nil {
				return nil
			}
			if err := json.Unmarshal(answer, into); err != nil {
				return fmt.Errorf("%s %s answered what does not read: %w", method, path, err)
			}
			return nil
		}
		refusal := refusalOf(status, answer)
		if status == http.StatusUnauthorized && c.auth.Token == "" && !renewed {
			// Five minutes, an exchanged credential lasts: an apply that outlives it trades again, once.
			renewed = true
			c.forget(credential)
			continue
		}
		if wait, ok := retryAfter(status, refusal, header); ok && attempt < 3 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		return refusal
	}
}

func (c *Client) send(ctx context.Context, method, path, credential string, payload []byte) (int, http.Header, []byte, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.origin+path, reader)
	if err != nil {
		return 0, nil, nil, err
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("user-agent", c.agent)
	request.Header.Set("authorization", "Bearer "+credential)
	if payload != nil {
		request.Header.Set("content-type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		// The error names the URL and the transport's failure, never the body sent.
		return 0, nil, nil, fmt.Errorf("%s %s%s: %w", method, c.origin, path, unwrapURL(err))
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return 0, nil, nil, err
	}
	return response.StatusCode, response.Header, answer, nil
}

func unwrapURL(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return urlError.Err
	}
	return err
}

func refusalOf(status int, answer []byte) *Error {
	var body struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	_ = json.Unmarshal(answer, &body)
	refusal := &Error{Status: status, Code: "http_error", Reason: body.Reason, Message: body.Message}
	switch e := body.Error.(type) {
	case string:
		refusal.Code = e
	case map[string]any:
		// An answer that nests its error: { error: { code, message, reason } }.
		if code, ok := e["code"].(string); ok {
			refusal.Code = code
		}
		if message, ok := e["message"].(string); ok && refusal.Message == "" {
			refusal.Message = message
		}
		if reason, ok := e["reason"].(string); ok && refusal.Reason == "" {
			refusal.Reason = reason
		}
	}
	if refusal.Message == "" {
		refusal.Message = http.StatusText(status)
	}
	return refusal
}

// retryAfter says how long to wait before asking again: coffre's answer
// to an overload (429, 503) or a write that met another (409 `changed`),
// each with a Retry-After of ten seconds at most.
func retryAfter(status int, refusal *Error, header http.Header) (time.Duration, bool) {
	if !(status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable || (status == http.StatusConflict && refusal.Reason == "changed")) {
		return 0, false
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(header.Get("retry-after")))
	if err != nil || seconds < 0 || seconds > 10 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// bearer returns the credential to send: the token given, or one traded
// for an ID token at `POST /api/auth/oidc`.
func (c *Client) bearer(ctx context.Context) (string, error) {
	if c.auth.Token != "" {
		return c.auth.Token, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credential != "" {
		return c.credential, nil
	}
	idToken, err := c.idToken(ctx)
	if err != nil {
		return "", err
	}
	credential, err := c.exchange(ctx, idToken)
	var unsent *transportError
	if c.auth.IDToken != "" && !errors.As(err, &unsent) {
		// Coffre saw the token: it is spent, whatever coffre answered. One
		// the network lost may be tried again, and coffre says if it arrived.
		c.spent = true
	}
	if err != nil {
		return "", err
	}
	c.credential = credential
	return credential, nil
}

// forget drops an exchanged credential coffre no longer takes, unless
// another call has replaced it meanwhile.
func (c *Client) forget(credential string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.credential == credential {
		c.credential = ""
	}
}

func (c *Client) idToken(ctx context.Context) (string, error) {
	if c.auth.IDToken != "" {
		if c.spent {
			return "", errors.New("the credential this phase traded its ID token for expired, and an ID token is spent once: run each phase within five minutes, or give the provider a token")
		}
		return c.auth.IDToken, nil
	}
	requestURL, bearer := strings.TrimSpace(c.runner("ACTIONS_ID_TOKEN_REQUEST_URL")), strings.TrimSpace(c.runner("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if requestURL == "" || bearer == "" {
		return "", fmt.Errorf("service %q signs in with the run's ID token, and there is none: on GitHub Actions, give the job `permissions: id-token: write`; elsewhere, set id_token (one per phase) or token", c.auth.Service)
	}
	address, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL does not read: %w", err)
	}
	query := address.Query()
	query.Set("audience", c.origin)
	address.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("authorization", "bearer "+bearer)
	request.Header.Set("accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("GitHub did not give this job an ID token: %w", unwrapURL(err))
	}
	defer response.Body.Close()
	var body struct {
		Value string `json:"value"`
	}
	_ = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&body)
	if response.StatusCode != http.StatusOK || body.Value == "" {
		return "", fmt.Errorf("GitHub did not give this job an ID token (status %d)", response.StatusCode)
	}
	return body.Value, nil
}

// ServiceMember is a service account as the API names it, `token:<name>`,
// from its name as people write it: `terraform-infra` or
// `service:terraform-infra`, as the CLI takes it.
func ServiceMember(name string) string {
	name = strings.TrimSpace(name)
	if rest, ok := strings.CutPrefix(name, "service:"); ok {
		return "token:" + rest
	}
	if strings.HasPrefix(name, "token:") {
		return name
	}
	return "token:" + name
}

// transportError is an exchange coffre did not answer.
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func (c *Client) exchange(ctx context.Context, idToken string) (string, error) {
	payload, err := json.Marshal(map[string]string{"service": ServiceMember(c.auth.Service), "token": idToken})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin+"/api/auth/oidc", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	request.Header.Set("user-agent", c.agent)
	response, err := c.http.Do(request)
	if err != nil {
		return "", &transportError{fmt.Errorf("POST %s/api/auth/oidc: %w", c.origin, unwrapURL(err))}
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if response.StatusCode == http.StatusOK {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(answer, &body); err == nil && body.Token != "" {
			return body.Token, nil
		}
		return "", fmt.Errorf("%s answered its exchange with no credential", c.origin)
	}
	refusal := refusalOf(response.StatusCode, answer)
	if refusal.Reason == "replayed" && c.auth.IDToken != "" {
		return "", errors.New(SpentIDToken)
	}
	return "", fmt.Errorf("%s would not sign this run in as %s: %w", c.origin, c.auth.Service, refusal)
}
