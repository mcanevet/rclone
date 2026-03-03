package protonapi

// client.go contains the ProtonClient struct, its constructor, the low-level
// HTTP helpers (doHTTP / handleResponseBytes / do / CallJSON / CallRaw /
// newAuthedRequest), and the UnwrapAPIError helper.
// It has zero dependency on rclone internals.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
)

const (
	// DefaultAPIURL is the production Proton API base URL.
	// Callers may override it by passing a non-empty apiURL to NewProtonClient.
	DefaultAPIURL = "https://drive-api.proton.me"

	// DefaultAppVersion is the default x-pm-appversion header value.
	// Callers may override it by passing a non-empty appVersion to NewProtonClient.
	DefaultAppVersion = "external-drive-rclone@1.0.0"
)

// SessionClient is the interface for the session-management subset of
// ProtonClient (credentials, keyrings, auth lifecycle). It is satisfied by
// *ProtonClient and can be embedded in product-specific client interfaces.
type SessionClient interface {
	// Auth
	Login(ctx context.Context, username, password string) (*Auth, error)
	Submit2FA(ctx context.Context, code string) error
	Logout(ctx context.Context) error

	// Credentials / keyrings
	UID() string
	AccessToken() string
	RefreshToken() string
	SetTokens(uid, accessToken, refreshToken string)
	GetUserKR() *pgpcrypto.KeyRing
	GetPrimaryKR() *pgpcrypto.KeyRing
	SetKeyrings(userKR *pgpcrypto.KeyRing, addrKRs map[string]*pgpcrypto.KeyRing, primaryKR *pgpcrypto.KeyRing)

	// User / keys / SRP
	GetUser(ctx context.Context) (*User, error)
	GetAddresses(ctx context.Context) ([]Address, error)
	GetKeySalts(ctx context.Context) ([]KeySalt, error)
	GetSRPModuli(ctx context.Context) (*SRPModuliResp, error)
}

// Ensure *ProtonClient implements SessionClient at compile time.
var _ SessionClient = (*ProtonClient)(nil)

// ProtonClient holds authentication state and an *http.Client for the
// Proton API. It has no dependency on rclone's lib/rest framework; all HTTP
// is done directly via net/http so the client can be used as a standalone SDK.
type ProtonClient struct {
	mu         sync.RWMutex
	httpClient *http.Client
	apiURL     string
	appVersion string

	// auth state (protected by mu)
	uid          string
	accessToken  string
	refreshToken string

	// refreshMu serialises token refresh so that when multiple goroutines
	// concurrently receive a 401, only one actually calls the refresh
	// endpoint; the rest wait and then reuse the new token.
	refreshMu sync.Mutex

	// unlocked keyrings — written once during bootstrapClient (before any
	// concurrent callers exist) and read-only thereafter. krMu guards
	// future token-refresh paths that may re-unlock keyrings.
	krMu      sync.RWMutex
	userKR    *pgpcrypto.KeyRing            // unlocked user keyring
	addrKRs   map[string]*pgpcrypto.KeyRing // email → unlocked address keyring
	primaryKR *pgpcrypto.KeyRing            // primary address keyring
}

// NewProtonClient creates a ProtonClient that talks to apiURL using httpClient.
// If apiURL is empty, DefaultAPIURL is used.
// If appVersion is empty, DefaultAppVersion is used.
func NewProtonClient(httpClient *http.Client, apiURL, appVersion string) (*ProtonClient, error) {
	if apiURL == "" {
		apiURL = DefaultAPIURL
	}
	if appVersion == "" {
		appVersion = DefaultAppVersion
	}
	return &ProtonClient{
		httpClient: httpClient,
		apiURL:     strings.TrimRight(apiURL, "/"),
		appVersion: appVersion,
		addrKRs:    make(map[string]*pgpcrypto.KeyRing),
	}, nil
}

// ---- low-level HTTP helpers ------------------------------------------------

// authHeaders returns the current Authorization and x-pm-uid header values.
// Must be called with c.mu held (or when single-threaded during bootstrap).
func (c *ProtonClient) authHeaders() (string, string) {
	return "Bearer " + c.accessToken, c.uid
}

// newAuthedRequest builds an HTTP request with the standard Proton API
// headers (app version, content type, auth token, UID).
func (c *ProtonClient) newAuthedRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-pm-appversion", c.appVersion)
	req.Header.Set("Content-Type", "application/json")
	c.mu.RLock()
	bearer, uid := c.authHeaders()
	hasToken := c.accessToken != ""
	hasUID := c.uid != ""
	c.mu.RUnlock()
	if hasToken {
		req.Header.Set("Authorization", bearer)
	}
	if hasUID {
		req.Header.Set("x-pm-uid", uid)
	}
	return req, nil
}

// doHTTP is the single-attempt transport layer: it marshals body (if non-nil),
// issues the request, reads the full response body, and returns the raw bytes.
// The body is always fully consumed so the underlying TCP connection can be
// reused by net/http.
func (c *ProtonClient) doHTTP(ctx context.Context, method, path string, body interface{}) (statusCode int, raw []byte, err error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := c.newAuthedRequest(ctx, method, c.apiURL+path, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response body: %w", err)
	}
	return resp.StatusCode, buf.Bytes(), nil
}

// handleResponseBytes decodes a raw API response into out, or returns a typed
// error. It is the decode layer that sits above doHTTP.
func (c *ProtonClient) handleResponseBytes(statusCode int, raw []byte, out interface{}, noResponse bool) error {
	if statusCode >= 200 && statusCode <= 299 {
		if noResponse || out == nil {
			return nil
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response (HTTP %d): %w", statusCode, err)
		}
		return nil
	}

	// Non-2xx: decode as API error.
	var apiErr Error
	if err := json.Unmarshal(raw, &apiErr); err == nil && apiErr.Message != "" {
		if statusCode >= 500 {
			return &RetryableError{Err: &apiErr}
		}
		return &apiErr
	}
	// Couldn't parse the body as an API error. For 401 responses, return a
	// typed *Error so that isHTTP401 can detect it for token refresh.
	if statusCode == 401 {
		return &Error{Code: 401, Message: fmt.Sprintf("HTTP %d (unparseable body)", statusCode)}
	}
	err := fmt.Errorf("HTTP %d", statusCode)
	if statusCode >= 500 {
		return &RetryableError{Err: err}
	}
	return err
}

// do executes a single attempt of a JSON API call.
func (c *ProtonClient) do(ctx context.Context, method, path string, body interface{}, out interface{}, noResponse bool) error {
	statusCode, raw, err := c.doHTTP(ctx, method, path, body)
	if err != nil {
		return err
	}
	return c.handleResponseBytes(statusCode, raw, out, noResponse)
}

// CallJSON performs a request and retries once on HTTP 401 by refreshing the
// token. Concurrent 401s are serialised via withRefresh (defined in auth.go).
func (c *ProtonClient) CallJSON(ctx context.Context, method, path string, body, out interface{}, noResponse bool) error {
	err := c.do(ctx, method, path, body, out, noResponse)
	if err == nil || !isHTTP401(err) {
		return err
	}
	return c.withRefresh(ctx, err, func() error {
		return c.do(ctx, method, path, body, out, noResponse)
	})
}

// CallJSONNoResp is a convenience wrapper around CallJSON for endpoints that
// return no response body (noResponse=true). It omits the out parameter.
func (c *ProtonClient) CallJSONNoResp(ctx context.Context, method, path string, body interface{}) error {
	return c.CallJSON(ctx, method, path, body, nil, true)
}

// CallRaw performs an authenticated request and retries once on HTTP 401.
// Unlike CallJSON it does not decode the response body — it returns the raw
// HTTP status code and body bytes so callers can perform their own decoding
// (e.g. to distinguish application-level error codes before the generic error
// decoder sees them).  Only network-level errors are returned as err; HTTP
// non-2xx status codes are surfaced via statusCode, not err.
func (c *ProtonClient) CallRaw(ctx context.Context, method, path string, body interface{}) (statusCode int, respBody []byte, err error) {
	statusCode, respBody, err = c.doHTTP(ctx, method, path, body)
	if err != nil {
		return statusCode, respBody, err
	}
	// Use the same typed-error 401 detection as CallJSON so both paths agree.
	apiErr := c.handleResponseBytes(statusCode, respBody, nil, true)
	if !isHTTP401(apiErr) {
		return statusCode, respBody, nil
	}
	retryErr := c.withRefresh(ctx, apiErr, func() error {
		statusCode, respBody, err = c.doHTTP(ctx, method, path, body)
		return err
	})
	return statusCode, respBody, retryErr
}

// APIURL returns the base API URL used by this client.
func (c *ProtonClient) APIURL() string { return c.apiURL }

// HTTPClient returns the underlying *http.Client.
// It is intentionally exported for callers that need to issue non-API requests
// (e.g. block storage uploads that use bare URLs without Proton auth headers).
func (c *ProtonClient) HTTPClient() *http.Client { return c.httpClient }

func isHTTP401(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr.Code == 401
	}
	return false
}

// UnwrapAPIError tries to extract an *Error from err.
func UnwrapAPIError(err error) (*Error, bool) {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr, true
	}
	return nil, false
}
