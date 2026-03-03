package protonapi

// keyrings.go contains the ProtonClient keyring and token accessor/mutator
// methods. These are kept separate from the HTTP logic to make it easy to
// see which state is guarded by which mutex.

import pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

// GetPrimaryKR returns the primary address keyring under a read lock.
func (c *ProtonClient) GetPrimaryKR() *pgpcrypto.KeyRing {
	c.krMu.RLock()
	defer c.krMu.RUnlock()
	return c.primaryKR
}

// GetUserKR returns the user keyring under a read lock.
func (c *ProtonClient) GetUserKR() *pgpcrypto.KeyRing {
	c.krMu.RLock()
	defer c.krMu.RUnlock()
	return c.userKR
}

// SetKeyrings sets the user, address, and primary keyrings atomically.
func (c *ProtonClient) SetKeyrings(userKR *pgpcrypto.KeyRing, addrKRs map[string]*pgpcrypto.KeyRing, primaryKR *pgpcrypto.KeyRing) {
	c.krMu.Lock()
	defer c.krMu.Unlock()
	c.userKR = userKR
	c.addrKRs = addrKRs
	c.primaryKR = primaryKR
}

// AddrKR returns the address keyring for the given email (may be nil).
// It performs a single lookup under a read lock, without copying the map.
func (c *ProtonClient) AddrKR(email string) *pgpcrypto.KeyRing {
	c.krMu.RLock()
	defer c.krMu.RUnlock()
	return c.addrKRs[email]
}

// SetTokens sets the uid, accessToken and refreshToken atomically.
func (c *ProtonClient) SetTokens(uid, accessToken, refreshToken string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.uid = uid
	c.accessToken = accessToken
	c.refreshToken = refreshToken
}

// UID returns the current UID.
func (c *ProtonClient) UID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uid
}

// AccessToken returns the current access token.
func (c *ProtonClient) AccessToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken
}

// RefreshToken returns the current refresh token.
func (c *ProtonClient) RefreshToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.refreshToken
}
