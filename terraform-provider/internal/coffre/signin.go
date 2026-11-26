package coffre

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Signer gives each request its bearer credential.
type Signer interface {
	// Bearer is the credential to send now.
	Bearer(ctx context.Context, c *Client) (string, error)
	// Renew forgets `used`, which coffre refused as expired, and says whether another can be had.
	Renew(used string) bool
}

// Token signs in with one credential: a service account's token (`coffre_svc_…`).
type Token string

func (t Token) Bearer(context.Context, *Client) (string, error) { return string(t), nil }
func (Token) Renew(string) bool                                 { return false }

// IDTokens gives a CI run's ID tokens, for an audience.
type IDTokens interface {
	IDToken(ctx context.Context, c *Client, audience string) (string, error)
	// Fresh says whether each call gives a new one, which an exchange has not spent.
	Fresh() bool
}

// GivenIDToken is one ID token, given in the configuration: it serves one exchange.
type GivenIDToken string

func (g GivenIDToken) IDToken(context.Context, *Client, string) (string, error) {
	return string(g), nil
}
func (GivenIDToken) Fresh() bool { return false }

// ActionsIDTokens asks GitHub's runner for a fresh ID token each time, as a job with
// `permissions: id-token: write` may: its ACTIONS_ID_TOKEN_REQUEST_URL and _TOKEN.
type ActionsIDTokens struct {
	URL, Token string
}

func (a ActionsIDTokens) Fresh() bool { return true }

func (a ActionsIDTokens) IDToken(ctx context.Context, c *Client, audience string) (string, error) {
	asked, err := url.Parse(a.URL)
	if err != nil {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL")
	}
	query := asked.Query()
	query.Set("audience", audience)
	asked.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asked.String(), nil)
	if err != nil {
		return "", errors.New("the ID token request could not be made")
	}
	request.Header.Set("authorization", "bearer "+a.Token)
	request.Header.Set("accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return "", errors.New("GitHub's runner did not answer the ID token request")
	}
	defer response.Body.Close()
	var body struct {
		Value string `json:"value"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(http.MaxBytesReader(nil, response.Body, 64<<10)).Decode(&body) != nil || body.Value == "" {
		return "", fmt.Errorf("GitHub's runner gave this job no ID token (status %d): does the job have `permissions: id-token: write`?", response.StatusCode)
	}
	return body.Value, nil
}

// OIDC signs in as a service account with a CI run's ID token, traded at
// POST /api/auth/oidc for a credential of five minutes, renewed before it
// expires.
type OIDC struct {
	// Service is the account's member id, `token:<name>`.
	Service  string
	IDTokens IDTokens
	// Now is the clock; tests replace it.
	Now func() time.Time

	mu      sync.Mutex
	current string
	expires time.Time
	traded  int
}

// ServiceMember names a service account as coffre does: `terraform` is `token:terraform`.
func ServiceMember(name string) string {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "token:") {
		return name
	}
	return "token:" + name
}

// Renewed a minute before it expires: a call signed just before then still lands.
const renewBefore = time.Minute

func (o *OIDC) Bearer(ctx context.Context, c *Client) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	// A credential is renewed a minute early only where a fresh ID token can renew it; one from a
	// given ID token, which cannot be, serves to its last second.
	early := time.Duration(0)
	if o.IDTokens.Fresh() {
		early = renewBefore
	}
	if o.current != "" && now.Add(early).Before(o.expires) {
		return o.current, nil
	}
	issued, err := o.exchange(ctx, c)
	if err != nil {
		return "", err
	}
	o.current = issued.Token
	o.expires = issued.ExpiresAt
	return o.current, nil
}

func (o *OIDC) Renew(used string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if used == o.current {
		o.current = ""
	}
	return o.IDTokens.Fresh()
}

func (o *OIDC) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

type issued struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// exchange trades an ID token for a credential. Asked again, within
// mostWaited, while coffre says to wait (429, 503), with a fresh ID token
// where the run can have one: an exchange that failed may still have spent it.
func (o *OIDC) exchange(ctx context.Context, c *Client) (issued, error) {
	waited, waits := time.Duration(0), 0
	for {
		if o.traded > 0 && !o.IDTokens.Fresh() {
			return issued{}, fmt.Errorf("the credential %s signed in with has expired, and the ID token given in oidc.id_token served its one exchange: an ID token signs in one run. In GitHub Actions, leave id_token out: the provider asks the runner for a fresh one", o.Service)
		}
		token, err := o.IDTokens.IDToken(ctx, c, c.origin)
		if err != nil {
			return issued{}, err
		}
		body, _ := json.Marshal(map[string]string{"service": o.Service, "token": token})
		status, header, answer, err := c.send(ctx, http.MethodPost, "/api/auth/oidc", body, "")
		if err != nil {
			return issued{}, fmt.Errorf("signing in as %s got no answer from coffre: %w", o.Service, err)
		}
		if status == http.StatusOK {
			var got issued
			if json.Unmarshal(answer, &got) != nil || got.Token == "" || got.ExpiresAt.IsZero() {
				return issued{}, errors.New("coffre's answer to the sign-in did not parse")
			}
			o.traded++
			return got, nil
		}
		refusal := refusalOf(status, answer)
		if wait, ok := retryAfter(header); ok && (status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable) && waited+wait <= mostWaited && waits < mostWaits {
			waited += wait
			waits++
			if err := c.Sleep(ctx, wait); err != nil {
				return issued{}, err
			}
			continue
		}
		return issued{}, signInRefused(o.Service, refusal, o.IDTokens.Fresh())
	}
}

func signInRefused(service string, refusal *Error, fresh bool) error {
	why := refusal.Error()
	switch {
	case refusal.Reason == "replayed" && !fresh:
		return fmt.Errorf("coffre would not sign in as %s: the ID token given in oidc.id_token was traded already, by an earlier run or the plan before this apply. An ID token signs in one run: give a fresh one, or in GitHub Actions leave id_token out. (%s)", service, why)
	case refusal.Status == http.StatusGone:
		return fmt.Errorf("this instance signs services in with a key only (useOnly), which this provider does not do yet: sign in with a token instead. (%s)", why)
	case refusal.Status == http.StatusNotFound:
		return fmt.Errorf("this instance trusts no CI runs: sign in with a token instead. (%s)", why)
	}
	return fmt.Errorf("coffre would not sign in as %s: %s", service, why)
}
