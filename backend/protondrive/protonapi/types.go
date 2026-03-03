// Package protonapi contains generic Proton API types and client logic that is
// not specific to any single Proton product (Drive, Mail, Calendar, …).
//
// It has zero dependency on rclone internals and zero dependency on
// protondriveapi so that it can be reused by any future Proton backend.
package protonapi

// ---- Common ----------------------------------------------------------------

// RetryableError wraps an error to signal that the operation is transient and
// may be retried. Callers check for it with errors.As.
type RetryableError struct {
	Err error
}

func (e *RetryableError) Error() string { return e.Err.Error() }
func (e *RetryableError) Unwrap() error { return e.Err }

// Error represents a Proton API error response body.
type Error struct {
	Code    int    `json:"Code"`
	Message string `json:"Error"`
}

func (e *Error) Error() string { return e.Message }

// Response is the base of every Proton API response (carries the Code field).
type Response struct {
	Code int `json:"Code"`
}

// ---- Auth ------------------------------------------------------------------

// AuthInfoReq is the body for POST /auth/v4/info.
type AuthInfoReq struct {
	Username string `json:"Username"`
	Intent   string `json:"Intent,omitempty"` // "Proton"
	ClientID string `json:"ClientID,omitempty"`
}

// AuthInfo is the response from POST /auth/v4/info.
type AuthInfo struct {
	Response
	Modulus         string `json:"Modulus"`
	ServerEphemeral string `json:"ServerEphemeral"`
	Version         int    `json:"Version"`
	Salt            string `json:"Salt"`
	SRPSession      string `json:"SRPSession"`
}

// AuthReq is the body for POST /auth/v4.
type AuthReq struct {
	Username        string `json:"Username"`
	ClientEphemeral string `json:"ClientEphemeral"`
	ClientProof     string `json:"ClientProof"`
	SRPSession      string `json:"SRPSession"`
}

// TwoFAInfo carries the nested 2FA status returned by the Proton auth
// endpoint. The API response shape is {"2FA": {"Enabled": 1}}.
type TwoFAInfo struct {
	Enabled int `json:"Enabled"`
}

// Auth is the response from POST /auth/v4.
type Auth struct {
	Response
	UID          string `json:"UID"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
	ServerProof  string `json:"ServerProof"`
	Scope        string `json:"Scope"`
	UserID       string `json:"UserID"`
	// TwoFA.Enabled > 0 means 2FA is required; 1 = TOTP, 2 = FIDO2, 3 = both
	TwoFA TwoFAInfo `json:"2FA"`
	// PasswordMode 1 = single-password, 2 = two-password (mailbox password needed)
	PasswordMode int `json:"PasswordMode,omitempty"`
}

// Auth2FAReq is the body for POST /auth/v4/2fa.
type Auth2FAReq struct {
	TwoFactorCode string `json:"TwoFactorCode"`
}

// AuthRefreshReq is the body for POST /auth/v4/refresh.
type AuthRefreshReq struct {
	UID          string `json:"UID"`
	RefreshToken string `json:"RefreshToken"`
	ResponseType string `json:"ResponseType"` // "token"
	GrantType    string `json:"GrantType"`    // "refresh_token"
	RedirectURI  string `json:"RedirectURI,omitempty"`
}

// AuthRefreshResp is the response from POST /auth/v4/refresh.
type AuthRefreshResp struct {
	Response
	UID          string `json:"UID"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"TokenType"`
}

// ---- User / Address / Keys -------------------------------------------------

// UserKey represents one of the user's PGP keys.
type UserKey struct {
	ID         string `json:"ID"`
	Version    int    `json:"Version"`
	PrivateKey string `json:"PrivateKey"` // armored
	Active     int    `json:"Active"`
	Primary    int    `json:"Primary"`
}

// User represents a Proton user.
type User struct {
	Response
	ID        string    `json:"ID"`
	Name      string    `json:"Name"`
	MaxSpace  int64     `json:"MaxSpace"`
	UsedSpace int64     `json:"UsedSpace"`
	Keys      []UserKey `json:"Keys"`
}

// AddressKey represents one of an address's PGP keys.
type AddressKey struct {
	ID         string `json:"ID"`
	Version    int    `json:"Version"`
	PrivateKey string `json:"PrivateKey"` // armored
	Active     int    `json:"Active"`
	Primary    int    `json:"Primary"`
	// Token and Signature are present for token-based address keys (modern accounts).
	// Token is an armored PGP message encrypted to the user key; decrypting it
	// yields the passphrase used to unlock PrivateKey.
	Token     string `json:"Token,omitempty"`
	Signature string `json:"Signature,omitempty"`
}

// Address represents a Proton address.
type Address struct {
	ID     string       `json:"ID"`
	Email  string       `json:"Email"`
	Status int          `json:"Status"` // 1 = enabled
	Type   int          `json:"Type"`
	Keys   []AddressKey `json:"Keys"`
}

// AddressesResp is the response from GET /core/v4/addresses.
type AddressesResp struct {
	Response
	Addresses []Address `json:"Addresses"`
}

// KeySalt holds the salt for a key (used to derive saltedKeyPass).
type KeySalt struct {
	ID      string `json:"ID"`
	KeySalt string `json:"KeySalt"` // base64-encoded
}

// KeySaltsResp is the response from GET /core/v4/keys/salts.
type KeySaltsResp struct {
	Response
	KeySalts []KeySalt `json:"KeySalts"`
}

// UserResp wraps User for GET /core/v4/users.
type UserResp struct {
	Response
	User User `json:"User"`
}

// ---- SRP Moduli ------------------------------------------------------------

// SRPModuliResp is the response from GET /auth/v4/modulus.
// Included here (rather than in protondriveapi) because GetSRPModuli is also
// needed for share-URL creation which is conceptually a generic auth helper.
type SRPModuliResp struct {
	Response
	Modulus   string `json:"Modulus"`   // PGP clear-signed modulus
	ModulusID string `json:"ModulusID"` // ID to reference in ShareURL creation
}
