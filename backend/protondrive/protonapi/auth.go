package protonapi

// auth.go contains the ProtonClient authentication methods: Login, Submit2FA,
// refreshAccessToken (internal), Logout, and the withRefresh helper that
// serialises concurrent token-refresh attempts.

import (
	"context"
	"encoding/base64"
	"fmt"

	srp "github.com/ProtonMail/go-srp"
)

// Login performs the full SRP authentication flow.
//  1. POST /auth/v4/info  → get modulus, salt, serverEphemeral
//  2. Compute SRP proofs
//  3. POST /auth/v4       → get UID, AccessToken, RefreshToken
func (c *ProtonClient) Login(ctx context.Context, username, password string) (*Auth, error) {
	// Step 1: get auth info
	var infoResp AuthInfo
	if err := c.CallJSON(ctx, "POST", "/auth/v4/info",
		&AuthInfoReq{Username: username, Intent: "Proton"}, &infoResp, false); err != nil {
		return nil, fmt.Errorf("login info: %w", err)
	}

	// Step 2: SRP proofs
	auth, err := srp.NewAuth(infoResp.Version, username, []byte(password),
		infoResp.Salt, infoResp.Modulus, infoResp.ServerEphemeral)
	if err != nil {
		return nil, fmt.Errorf("login srp auth: %w", err)
	}
	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return nil, fmt.Errorf("login srp proofs: %w", err)
	}

	// Step 3: authenticate
	var authResp Auth
	if err := c.CallJSON(ctx, "POST", "/auth/v4", &AuthReq{
		Username:        username,
		ClientEphemeral: base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		ClientProof:     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		SRPSession:      infoResp.SRPSession,
	}, &authResp, false); err != nil {
		return nil, fmt.Errorf("login auth: %w", err)
	}

	// Verify server proof
	if base64.StdEncoding.EncodeToString(proofs.ExpectedServerProof) != authResp.ServerProof {
		return nil, fmt.Errorf("login: server proof mismatch")
	}

	c.mu.Lock()
	c.uid = authResp.UID
	c.accessToken = authResp.AccessToken
	c.refreshToken = authResp.RefreshToken
	c.mu.Unlock()

	return &authResp, nil
}

// Submit2FA sends the TOTP code after a successful SRP auth when 2FA is required.
func (c *ProtonClient) Submit2FA(ctx context.Context, code string) error {
	return c.CallJSON(ctx, "POST", "/auth/v4/2fa", &Auth2FAReq{TwoFactorCode: code}, &Response{}, false)
}

// refreshAccessToken uses the stored refresh token to get new credentials.
func (c *ProtonClient) refreshAccessToken(ctx context.Context) error {
	c.mu.Lock()
	uid := c.uid
	refreshToken := c.refreshToken
	c.mu.Unlock()

	var resp AuthRefreshResp
	// Use do directly (not callJSON) to avoid an infinite retry loop.
	if err := c.do(ctx, "POST", "/auth/v4/refresh", &AuthRefreshReq{
		UID:          uid,
		RefreshToken: refreshToken,
		ResponseType: "token",
		GrantType:    "refresh_token",
	}, &resp, false); err != nil {
		return fmt.Errorf("refreshAccessToken: %w", err)
	}

	if resp.AccessToken == "" || resp.RefreshToken == "" || resp.UID == "" {
		return fmt.Errorf("refreshAccessToken: server returned empty token fields")
	}

	c.mu.Lock()
	c.uid = resp.UID
	c.accessToken = resp.AccessToken
	c.refreshToken = resp.RefreshToken
	c.mu.Unlock()
	return nil
}

// Logout deletes the current auth session.
func (c *ProtonClient) Logout(ctx context.Context) error {
	return c.CallJSON(ctx, "DELETE", "/auth/v4", nil, nil, true)
}

// withRefresh retries fn once after a token refresh when fn returns an HTTP 401.
// Concurrent 401s are serialised: only one goroutine calls the refresh endpoint;
// the others wait, then retry with the updated token without triggering another
// refresh. origErr is the 401 error returned by the first call to fn.
func (c *ProtonClient) withRefresh(ctx context.Context, origErr error, fn func() error) error {
	// Snapshot the token that was rejected so we can detect whether a
	// concurrent goroutine already refreshed it while we waited.
	c.mu.Lock()
	tokenBeforeWait := c.accessToken
	refreshToken := c.refreshToken
	c.mu.Unlock()

	if refreshToken == "" {
		return origErr
	}

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	// Another goroutine may have refreshed while we waited for the lock.
	c.mu.Lock()
	tokenNow := c.accessToken
	c.mu.Unlock()
	if tokenNow == tokenBeforeWait {
		// We are the first: refresh.
		if refreshErr := c.refreshAccessToken(ctx); refreshErr != nil {
			return fmt.Errorf("token refresh failed: %w (original 401: %v)", refreshErr, origErr)
		}
	}

	// Retry the original operation with the updated token.
	return fn()
}
