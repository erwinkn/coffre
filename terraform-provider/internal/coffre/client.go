// Package coffre is the provider's client for coffre's API (/api): the calls
// the provider makes, how it signs in, and how it reads a refusal. Nothing
// here logs or returns what it sent: a write's body holds a value.
package coffre

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Most of a response read: a listing of a large environment fits many times over.
const mostRead = 32 << 20

// How long the client waits, in all, on the Retry-After of 429s and 503s for one call.
const mostWaited = time.Minute

// Client calls one coffre instance as one member: a service account, by its
// token or a CI run's ID token, or a person, by their saved session.
type Client struct {
	origin    string
	http      *http.Client
	signer    Signer
	userAgent string
	listed    listings
	projects  projects
	// Sleep waits between attempts; tests replace it.
	Sleep func(context.Context, time.Duration) error
}

// Origin parses an instance's URL into its origin, as the CLI names an
// instance: `https://host[:port]`, or `http` on loopback for a local one. A
// path, a query or credentials in it are refused rather than dropped.
func Origin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	// A URL with credentials in it is not repeated: they may be a password.
	if strings.Contains(raw, "@") && (err != nil || parsed.User != nil) {
		return "", errors.New("the URL holds credentials: give only the instance's scheme and host, such as https://secrets.acme.example, and sign in with token or oidc")
	}
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("%q is not a URL: give the instance's, such as https://secrets.acme.example", raw)
	}
	if (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%q is more than an instance's URL: give only its scheme and host, such as https://secrets.acme.example", raw)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !loopback(parsed.Hostname()) {
			return "", fmt.Errorf("%q is plain http: a credential goes to coffre over https only, or http on loopback for a local instance", raw)
		}
	default:
		return "", fmt.Errorf("%q is not an https URL", raw)
	}
	// As a browser, and so `coffre login`, names it: the host in lowercase, a default port left out.
	host, port := strings.ToLower(parsed.Hostname()), parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return parsed.Scheme + "://" + host, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// New is a client of the instance at `origin` (see Origin), signed in by `signer`.
func New(origin string, signer Signer, userAgent string) *Client {
	return &Client{
		origin: origin,
		http: &http.Client{
			Timeout: 60 * time.Second,
			// A credential never follows a redirect to another host, nor to the same one: coffre's API sends none.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		signer:    signer,
		userAgent: userAgent,
		Sleep: func(ctx context.Context, wait time.Duration) error {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}
}

// Error is a refusal, as coffre answers one: `{ "error": code, "reason"?, "message" }`.
// The message is written to be shown; nothing the request sent is in it.
type Error struct {
	Status  int
	Code    string
	Reason  string
	Message string
}

func (e *Error) Error() string {
	reason := ""
	if e.Reason != "" {
		reason = ", " + e.Reason
	}
	message := e.Message
	if message == "" {
		message = http.StatusText(e.Status)
	}
	return fmt.Sprintf("coffre answered %d (%s%s): %s", e.Status, e.Code, reason, message)
}

// Is reports whether err is coffre's refusal with this status and, if given, this reason.
func Is(err error, status int, reason string) bool {
	var refused *Error
	return errors.As(err, &refused) && refused.Status == status && (reason == "" || refused.Reason == reason)
}

// call sends one request to /api, signed, and decodes its answer into `out`.
// A GET is asked again when the connection drops; any call when coffre says
// to wait (429, or 503 for a GET), within mostWaited. A write that got no
// answer is never sent again: it may have been made.
func (c *Client) call(ctx context.Context, method, path string, body any, out any) error {
	var sent []byte
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return errors.New("the request could not be encoded")
		}
		sent = encoded
	}
	read := method == http.MethodGet
	renewed := false
	waited, waits := time.Duration(0), 0
	for attempt := 0; ; attempt++ {
		bearer, err := c.signer.Bearer(ctx, c)
		if err != nil {
			return err
		}
		status, header, answer, err := c.send(ctx, method, "/api"+path, sent, bearer)
		if err != nil {
			if read && attempt < 3 && ctx.Err() == nil {
				if err := c.Sleep(ctx, time.Duration(attempt+1)*time.Second); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("%s %s got no answer from coffre: %w", method, path, err)
		}
		if status >= 200 && status < 300 {
			if out == nil || len(answer) == 0 {
				return nil
			}
			if err := json.Unmarshal(answer, out); err != nil {
				return fmt.Errorf("%s %s: coffre's answer did not parse (%d bytes)", method, path, len(answer))
			}
			return nil
		}
		refusal := refusalOf(status, answer)
		// An expired credential: a CI run's is renewed once, with a fresh ID token.
		if status == http.StatusUnauthorized && !renewed && c.signer.Renew(bearer) {
			renewed = true
			continue
		}
		if _, person := c.signer.(*Session); person && status == http.StatusUnauthorized {
			return fmt.Errorf("%w. The session `coffre login` saved for %s ended or was revoked: run `coffre login %s` again", refusal, c.origin, c.origin)
		}
		if wait, ok := retryAfter(header); ok && (status == http.StatusTooManyRequests || (status == http.StatusServiceUnavailable && read)) && waited+wait <= mostWaited && waits < mostWaits {
			waited += wait
			waits++
			if err := c.Sleep(ctx, wait); err != nil {
				return err
			}
			continue
		}
		return refusal
	}
}

// send makes one HTTP request and reads its answer, to mostRead.
func (c *Client) send(ctx context.Context, method, path string, body []byte, bearer string) (int, http.Header, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.origin+path, reader)
	if err != nil {
		return 0, nil, nil, errors.New("the request could not be made")
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("user-agent", c.userAgent)
	if body != nil {
		request.Header.Set("content-type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("authorization", "Bearer "+bearer)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, nil, scrub(err, c.origin)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(response.Body, mostRead+1))
	if err != nil {
		return 0, nil, nil, errors.New("the answer was cut off")
	}
	if len(answer) > mostRead {
		return 0, nil, nil, fmt.Errorf("the answer is over %d MiB", mostRead>>20)
	}
	return response.StatusCode, response.Header, answer, nil
}

// scrub keeps what an error from net/http says of the connection, and only that:
// it names the URL, which holds no secret, but nothing of the request's body or headers.
func scrub(err error, origin string) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return fmt.Errorf("%s: %w", origin, urlError.Err)
	}
	return err
}

func refusalOf(status int, answer []byte) *Error {
	var body struct {
		Error   string `json:"error"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(answer, &body)
	if body.Error == "" {
		body.Error = strings.ReplaceAll(strings.ToLower(http.StatusText(status)), " ", "_")
	}
	return &Error{Status: status, Code: body.Error, Reason: body.Reason, Message: body.Message}
}

// mostWaits is how many times a call waits when told to: a few, as well as within mostWaited.
const mostWaits = 5

// retryAfter reads a Retry-After in seconds, as coffre sends it: a wait of at least a second, and
// none at all (ok false) past mostWaited, which no retry within it could honour.
func retryAfter(header http.Header) (time.Duration, bool) {
	seconds, err := strconv.Atoi(strings.TrimSpace(header.Get("retry-after")))
	if err != nil || seconds < 0 || seconds > int(mostWaited/time.Second) {
		return 0, false
	}
	return time.Duration(max(seconds, 1)) * time.Second, true
}
