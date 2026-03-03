package protondrive

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	protonbcrypt "github.com/ProtonMail/bcrypt"
	srp "github.com/ProtonMail/go-srp"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/rclone/rclone/backend/protondrive/protonapi"
	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
)

const (
	// shareURLReadPermissions is the permissions value for a read-only public link.
	shareURLReadPermissions = 4
	// shareURLFlagRandomPassword means the link uses a random password.
	shareURLFlagRandomPassword = 2
	// publicLinkPasswordLen is the length of the generated random password.
	publicLinkPasswordLen = 12
)

// publicLinkPasswordChars is the charset for random public link passwords.
const publicLinkPasswordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// generatePublicLinkPassword generates a random alphanumeric password of
// publicLinkPasswordLen characters, matching the Proton Drive web app behaviour.
func generatePublicLinkPassword() (string, error) {
	const charsetLen = len(publicLinkPasswordChars)
	// Largest multiple of charsetLen that fits in a byte — values >= this
	// threshold are rejected to eliminate modulo bias.
	const maxUnbiased = (256 / charsetLen) * charsetLen // = 248 for 62 chars

	// Draw random bytes in batches to avoid calling RandomToken once per
	// character. 64 bytes is enough for 12 output characters even after
	// worst-case rejection (~3% of bytes are discarded).
	const bufSize = 64
	var buf []byte
	var bufPos int

	result := make([]byte, publicLinkPasswordLen)
	for i := range result {
		for {
			if bufPos >= len(buf) {
				var err error
				buf, err = pgpcrypto.RandomToken(bufSize)
				if err != nil {
					return "", fmt.Errorf("generatePublicLinkPassword: %w", err)
				}
				bufPos = 0
			}
			b := buf[bufPos]
			bufPos++
			if int(b) < maxUnbiased {
				result[i] = publicLinkPasswordChars[int(b)%charsetLen]
				break
			}
		}
	}
	return string(result), nil
}

// computeBcryptPassphrase derives the bcrypt passphrase from the generated
// password and a random salt, following the Proton Drive SDK algorithm:
//
//	hash = bcrypt(password, "$2y$10$" + bcrypt_base64(salt, 16))
//	passphrase = hash[29:]
//
// Returns the passphrase and the standard-base64-encoded salt for storage in
// the API (SharePasswordSalt field).
func computeBcryptPassphrase(password string, salt []byte) (passphrase string, saltB64 string, err error) {
	// bcryptBase64 is the bcrypt-custom base64 alphabet (uses . instead of +,
	// starts with ./, no padding). It is used to encode the salt before
	// constructing the bcrypt cost string that the Proton SDK expects.
	bcryptBase64 := base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

	// Encode the 16-byte salt using bcrypt's custom alphabet (22 chars, no pad).
	encodedSalt := bcryptBase64.EncodeToString(salt)
	costString := "$2y$10$" + encodedSalt

	hash, err := protonbcrypt.HashBytes([]byte(password), []byte(costString))
	if err != nil {
		return "", "", fmt.Errorf("computeBcryptPassphrase: bcrypt: %w", err)
	}
	// The 29-byte prefix is "$2y$10$" (7 chars) + 22-char encoded salt = 29 chars.
	const prefixLen = 29
	if len(hash) < prefixLen {
		return "", "", fmt.Errorf("computeBcryptPassphrase: unexpected bcrypt hash length %d", len(hash))
	}
	passphrase = string(hash[prefixLen:])
	saltB64 = base64.StdEncoding.EncodeToString(salt)
	return passphrase, saltB64, nil
}

// shareForLink holds the share ID and the session key of the share passphrase,
// which is needed to build the ShareURL crypto payload.
type shareForLink struct {
	shareID              string
	passphraseSessionKey *pgpcrypto.SessionKey
}

// decryptLinkName decrypts an armored PGP link name using the parent keyring.
// If decryption fails for any reason, it returns the fallback "New Share" so
// that share creation is not blocked by a cosmetic name issue.
func decryptLinkName(armoredName string, parentKR *pgpcrypto.KeyRing) string {
	if armoredName == "" || parentKR == nil {
		return "New Share"
	}
	nameMsg, err := pgpcrypto.NewPGPMessageFromArmored(armoredName)
	if err != nil {
		return "New Share"
	}
	plain, err := parentKR.Decrypt(nameMsg, nil, pgpcrypto.GetUnixTime())
	if err != nil {
		return "New Share"
	}
	name := string(plain.GetBinary())
	if name == "" {
		return "New Share"
	}
	return name
}

// getOrCreateShareForLink returns the shareID and the share passphrase session
// key for an existing per-node share rooted at linkID, or creates one.
//
// The Proton Drive public-link flow requires a dedicated standard share per
// node (not the main files share), so that only the shared node is exposed.
func (f *Fs) getOrCreateShareForLink(ctx context.Context, linkID string) (*shareForLink, error) {
	addrKR := f.client.GetPrimaryKR()
	if addrKR == nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: no primary address keyring")
	}

	// Fetch the link so we can get its node passphrase and name fields.
	link, err := f.getLink(ctx, linkID)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: %w", err)
	}

	// Unlock the node's own keyring (needed for the combined encryption target).
	nodeKR, err := f.unlockLink(ctx, linkID)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: unlock link: %w", err)
	}

	// Unlock the parent's keyring: node passphrase and name are both encrypted
	// to the parent's keyring (not the node's own KR).
	parentKR, err := f.unlockLink(ctx, link.Link.ParentLinkID)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: unlock parent link: %w", err)
	}

	// Extract the node's passphrase session key (from NodePassphrase, encrypted
	// to parentKR).
	nodePPSK, err := extractSessionKey(link.Link.NodePassphrase, parentKR)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: extract node passphrase SK: %w", err)
	}

	// Extract the node's name session key (from Name, encrypted to parentKR).
	nameSessionKey, err := extractSessionKey(link.Link.Name, parentKR)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: extract name SK: %w", err)
	}

	// Build a combined keyring of [nodeKR, addrKR] so the share passphrase is
	// encrypted to both, matching the SDK: generateKey([nodeKeys.key, addressKey]).
	combinedKR, err := combinePublicKeyRings(nodeKR, addrKR)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: combine keyrings: %w", err)
	}

	// Generate the share key pair. The passphrase is encrypted to combinedKR
	// (both node key and address key) and signed with addrKR.
	shareKeyArmored, sharePassphraseEnc, sharePassphraseSig, err := protondriveapi.GenerateNodeKeys(combinedKR, addrKR)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: generate share keys: %w", err)
	}

	// Unlock the new share key (decrypt sharePassphraseEnc with addrKR).
	shareKR, err := unlockShareKey(shareKeyArmored, sharePassphraseEnc, addrKR)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: unlock share key: %w", err)
	}

	// Extract the share passphrase session key (encrypted to addrKR within
	// sharePassphraseEnc) so it can later be re-encrypted for the ShareURL.
	sharePPSK, err := extractSessionKey(sharePassphraseEnc, addrKR)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: extract share passphrase SK: %w", err)
	}

	// PassphraseKeyPacket = node passphrase session key re-encrypted to shareKR.
	passphraseKeyPacketBytes, err := shareKR.EncryptSessionKey(nodePPSK)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: encrypt passphrase SK to share: %w", err)
	}
	passphraseKeyPacket := base64.StdEncoding.EncodeToString(passphraseKeyPacketBytes)

	// NameKeyPacket = node name session key re-encrypted to shareKR.
	nameKeyPacketBytes, err := shareKR.EncryptSessionKey(nameSessionKey)
	if err != nil {
		return nil, fmt.Errorf("getOrCreateShareForLink: encrypt name SK to share: %w", err)
	}
	nameKeyPacket := base64.StdEncoding.EncodeToString(nameKeyPacketBytes)

	req := &protondriveapi.CreateStandardShareReq{
		AddressID:                f.addrID,
		RootLinkID:               linkID,
		Name:                     decryptLinkName(link.Link.Name, parentKR),
		ShareKey:                 shareKeyArmored,
		SharePassphrase:          sharePassphraseEnc,
		SharePassphraseSignature: sharePassphraseSig,
		PassphraseKeyPacket:      passphraseKeyPacket,
		NameKeyPacket:            nameKeyPacket,
	}

	var newShareID string
	if err := f.pacer.Call(func() (bool, error) {
		var callErr error
		newShareID, callErr = f.client.CreateStandardShare(ctx, f.volumeID, req)
		return shouldRetry(ctx, callErr)
	}); err != nil {
		// If a share already exists on this link, fall back to reusing it.
		if isShareAlreadyExistsError(err) {
			return f.getExistingShareForLink(ctx, linkID, nodeKR, addrKR)
		}
		return nil, fmt.Errorf("getOrCreateShareForLink: %w", err)
	}
	return &shareForLink{shareID: newShareID, passphraseSessionKey: sharePPSK}, nil
}

// isShareAlreadyExistsError reports whether err is a Proton API error
// indicating that a share already exists for the given link.
func isShareAlreadyExistsError(err error) bool {
	apiErr, ok := protonapi.UnwrapAPIError(err)
	if !ok {
		return false
	}
	// The server returns Code 2500 (ShareConflict) when a share already exists
	// on the given link.  Per the OpenAPI spec, this is the only meaning of
	// 2500 on POST /drive/volumes/{volumeID}/shares.
	return apiErr.Code == protondriveapi.CodeNameConflict
}

// getExistingShareForLink retrieves an existing per-node share for linkID,
// unlocks its passphrase using nodeKR (then addrKR as fallback), and returns
// the shareForLink suitable for building a ShareURL.
func (f *Fs) getExistingShareForLink(ctx context.Context, linkID string, nodeKR, addrKR *pgpcrypto.KeyRing) (*shareForLink, error) {
	var existingShareID string
	if err := f.pacer.Call(func() (bool, error) {
		var callErr error
		existingShareID, callErr = f.client.FindShareIDForLink(ctx, f.volumeID, linkID)
		return shouldRetry(ctx, callErr)
	}); err != nil {
		return nil, fmt.Errorf("getExistingShareForLink: find share: %w", err)
	}
	if existingShareID == "" {
		return nil, fmt.Errorf("getExistingShareForLink: no existing share found for link %s", linkID)
	}

	var share *protondriveapi.Share
	if err := f.pacer.Call(func() (bool, error) {
		var callErr error
		share, callErr = f.client.GetShare(ctx, existingShareID)
		return shouldRetry(ctx, callErr)
	}); err != nil {
		return nil, fmt.Errorf("getExistingShareForLink: get share: %w", err)
	}

	// The share passphrase may be encrypted to nodeKR (modern) or addrKR
	// (legacy). Try nodeKR first, then addrKR.
	sk, err := extractSessionKey(share.Passphrase, nodeKR)
	if err != nil {
		sk, err = extractSessionKey(share.Passphrase, addrKR)
		if err != nil {
			return nil, fmt.Errorf("getExistingShareForLink: decrypt share passphrase: %w", err)
		}
	}
	return &shareForLink{shareID: existingShareID, passphraseSessionKey: sk}, nil
}

// extractSessionKey splits an armored PGP message and decrypts the session key
// using the given keyring. Returns the session key for re-encryption.
func extractSessionKey(armoredMsg string, kr *pgpcrypto.KeyRing) (*pgpcrypto.SessionKey, error) {
	split, err := pgpcrypto.NewPGPSplitMessageFromArmored(armoredMsg)
	if err != nil {
		return nil, fmt.Errorf("extractSessionKey: split: %w", err)
	}
	sk, err := kr.DecryptSessionKey(split.GetBinaryKeyPacket())
	if err != nil {
		return nil, fmt.Errorf("extractSessionKey: decrypt: %w", err)
	}
	return sk, nil
}

// combinePublicKeyRings creates a new KeyRing containing the public keys from
// both a and b. This is needed to encrypt a message to multiple recipients.
func combinePublicKeyRings(a, b *pgpcrypto.KeyRing) (*pgpcrypto.KeyRing, error) {
	combined, err := pgpcrypto.NewKeyRing(nil)
	if err != nil {
		return nil, fmt.Errorf("combinePublicKeyRings: create ring: %w", err)
	}
	for _, k := range a.GetKeys() {
		pk, err := k.ToPublic()
		if err != nil {
			return nil, fmt.Errorf("combinePublicKeyRings: to public (a): %w", err)
		}
		if err := combined.AddKey(pk); err != nil {
			return nil, fmt.Errorf("combinePublicKeyRings: add key (a): %w", err)
		}
	}
	for _, k := range b.GetKeys() {
		pk, err := k.ToPublic()
		if err != nil {
			return nil, fmt.Errorf("combinePublicKeyRings: to public (b): %w", err)
		}
		if err := combined.AddKey(pk); err != nil {
			return nil, fmt.Errorf("combinePublicKeyRings: add key (b): %w", err)
		}
	}
	return combined, nil
}

// unlockShareKey decrypts sharePassphraseEnc using addrKR to obtain the
// passphrase, then unlocks shareKeyArmored with that passphrase, returning a
// KeyRing containing the unlocked share private key.
func unlockShareKey(shareKeyArmored, sharePassphraseEnc string, addrKR *pgpcrypto.KeyRing) (*pgpcrypto.KeyRing, error) {
	// Decrypt the share passphrase from the armored PGP message.
	passMsg, err := pgpcrypto.NewPGPMessageFromArmored(sharePassphraseEnc)
	if err != nil {
		return nil, fmt.Errorf("unlockShareKey: parse passphrase message: %w", err)
	}
	decPass, err := addrKR.Decrypt(passMsg, nil, pgpcrypto.GetUnixTime())
	if err != nil {
		return nil, fmt.Errorf("unlockShareKey: decrypt passphrase: %w", err)
	}
	// Unlock the share key with the decrypted passphrase.
	shareLockedKey, err := pgpcrypto.NewKeyFromArmored(shareKeyArmored)
	if err != nil {
		return nil, fmt.Errorf("unlockShareKey: parse share key: %w", err)
	}
	shareUnlockedKey, err := shareLockedKey.Unlock(decPass.GetBinary())
	if err != nil {
		return nil, fmt.Errorf("unlockShareKey: unlock share key: %w", err)
	}
	shareKR, err := pgpcrypto.NewKeyRing(shareUnlockedKey)
	if err != nil {
		return nil, fmt.Errorf("unlockShareKey: create share keyring: %w", err)
	}
	return shareKR, nil
}

// buildSharePassphraseKeyPacket symmetrically re-encrypts the share passphrase
// session key with bcryptPassphrase, returning a base64-encoded key packet for
// use in CreateShareURLReq.SharePassphraseKeyPacket.
func buildSharePassphraseKeyPacket(sk *pgpcrypto.SessionKey, bcryptPassphrase string) (string, error) {
	keyPacketBytes, err := pgpcrypto.EncryptSessionKeyWithPassword(sk, []byte(bcryptPassphrase))
	if err != nil {
		return "", fmt.Errorf("buildSharePassphraseKeyPacket: encrypt with password: %w", err)
	}
	return base64.StdEncoding.EncodeToString(keyPacketBytes), nil
}

// encryptPasswordForOwner PGP-encrypts the plaintext password to the address
// keyring (for owner recovery) and returns the armored ciphertext.
func encryptPasswordForOwner(password string, addrKR *pgpcrypto.KeyRing) (string, error) {
	plain := pgpcrypto.NewPlainMessageFromString(password)
	encMsg, err := addrKR.Encrypt(plain, addrKR)
	if err != nil {
		return "", fmt.Errorf("encryptPasswordForOwner: encrypt: %w", err)
	}
	armored, err := encMsg.GetArmored()
	if err != nil {
		return "", fmt.Errorf("encryptPasswordForOwner: armor: %w", err)
	}
	return armored, nil
}

// PublicLink creates or returns a public sharing link for the remote.
// If unlink is true, existing share URLs are deleted and "" is returned.
// Implements fs.PublicLinker.
func (f *Fs) PublicLink(ctx context.Context, remote string, expire fs.Duration, unlink bool) (string, error) {
	// Resolve remote to a linkID
	sanitized := f.sanitizePath(remote)
	var linkID string
	if sanitized == "" {
		// Share the root of this remote (which may be a sub-directory)
		var err error
		linkID, err = f.dirCache.RootID(ctx, false)
		if err != nil {
			return "", fmt.Errorf("PublicLink: get root ID: %w", err)
		}
	} else {
		leaf, folderLinkID, err := f.dirCache.FindPath(ctx, sanitized, false)
		if err != nil {
			return "", fmt.Errorf("PublicLink: find path: %w", err)
		}
		// Try file first, then folder
		link, err := f.findLinkByName(ctx, folderLinkID, leaf, false)
		if err != nil {
			return "", fmt.Errorf("PublicLink: find file: %w", err)
		}
		if link == nil {
			link, err = f.findLinkByName(ctx, folderLinkID, leaf, true)
			if err != nil {
				return "", fmt.Errorf("PublicLink: find folder: %w", err)
			}
		}
		if link == nil {
			return "", fs.ErrorObjectNotFound
		}
		linkID = link.Link.LinkID
	}

	// Get or create a per-node share for this link
	shareInfo, err := f.getOrCreateShareForLink(ctx, linkID)
	if err != nil {
		return "", fmt.Errorf("PublicLink: get/create share: %w", err)
	}

	// If unlinking, delete all existing ShareURLs for this share
	if unlink {
		var urls []protondriveapi.ShareURLData
		if err := f.pacer.Call(func() (bool, error) {
			var callErr error
			urls, callErr = f.client.ListShareURLs(ctx, shareInfo.shareID)
			return shouldRetry(ctx, callErr)
		}); err != nil {
			return "", fmt.Errorf("PublicLink: list share URLs: %w", err)
		}
		if len(urls) > 0 {
			ids := make([]string, len(urls))
			for i, u := range urls {
				ids[i] = u.ShareURLID
			}
			if err := f.pacer.Call(func() (bool, error) {
				callErr := f.client.DeleteShareURLs(ctx, shareInfo.shareID, ids)
				return shouldRetry(ctx, callErr)
			}); err != nil {
				return "", fmt.Errorf("PublicLink: delete share URLs: %w", err)
			}
		}
		return "", nil
	}

	// Check if a ShareURL already exists for this share and return it
	var existingURLs []protondriveapi.ShareURLData
	if err := f.pacer.Call(func() (bool, error) {
		var callErr error
		existingURLs, callErr = f.client.ListShareURLs(ctx, shareInfo.shareID)
		return shouldRetry(ctx, callErr)
	}); err != nil {
		return "", fmt.Errorf("PublicLink: list share URLs: %w", err)
	}
	// Note: we can't reconstruct the password from an existing ShareURL (it's
	// stored encrypted), so we always create a fresh one. Delete existing first.
	if len(existingURLs) > 0 {
		ids := make([]string, len(existingURLs))
		for i, u := range existingURLs {
			ids[i] = u.ShareURLID
		}
		if err := f.pacer.Call(func() (bool, error) {
			callErr := f.client.DeleteShareURLs(ctx, shareInfo.shareID, ids)
			return shouldRetry(ctx, callErr)
		}); err != nil {
			return "", fmt.Errorf("PublicLink: delete old share URLs: %w", err)
		}
	}

	addrKR := f.client.GetPrimaryKR()
	if addrKR == nil {
		return "", fmt.Errorf("PublicLink: no primary address keyring")
	}

	// Generate random 12-char password
	password, err := generatePublicLinkPassword()
	if err != nil {
		return "", fmt.Errorf("PublicLink: generate password: %w", err)
	}

	// Generate bcrypt salt (16 bytes) and derive bcrypt passphrase
	bcryptSalt, err := pgpcrypto.RandomToken(16)
	if err != nil {
		return "", fmt.Errorf("PublicLink: generate bcrypt salt: %w", err)
	}
	bcryptPassphrase, sharePasswordSaltB64, err := computeBcryptPassphrase(password, bcryptSalt)
	if err != nil {
		return "", fmt.Errorf("PublicLink: compute bcrypt passphrase: %w", err)
	}

	// Get SRP modulus from Proton API
	var moduliResp *protondriveapi.SRPModuliResp
	if err := f.pacer.Call(func() (bool, error) {
		var callErr error
		moduliResp, callErr = f.client.GetSRPModuli(ctx)
		return shouldRetry(ctx, callErr)
	}); err != nil {
		return "", fmt.Errorf("PublicLink: get SRP moduli: %w", err)
	}

	// Generate random 16-byte SRP salt
	srpSalt, err := pgpcrypto.RandomToken(16)
	if err != nil {
		return "", fmt.Errorf("PublicLink: generate SRP salt: %w", err)
	}
	urlPasswordSaltB64 := base64.StdEncoding.EncodeToString(srpSalt)

	// Build SRP verifier
	srpAuth, err := srp.NewAuthForVerifier([]byte(bcryptPassphrase), moduliResp.Modulus, srpSalt)
	if err != nil {
		return "", fmt.Errorf("PublicLink: SRP NewAuthForVerifier: %w", err)
	}
	verifierBytes, err := srpAuth.GenerateVerifier(2048)
	if err != nil {
		return "", fmt.Errorf("PublicLink: SRP GenerateVerifier: %w", err)
	}
	srpVerifierB64 := base64.StdEncoding.EncodeToString(verifierBytes)

	// Re-encrypt the share's passphrase session key with the bcrypt passphrase
	sharePassphraseKeyPacket, err := buildSharePassphraseKeyPacket(shareInfo.passphraseSessionKey, bcryptPassphrase)
	if err != nil {
		return "", fmt.Errorf("PublicLink: build passphrase key packet: %w", err)
	}

	// PGP-encrypt the plaintext password to the address key (for owner recovery)
	armoredPassword, err := encryptPasswordForOwner(password, addrKR)
	if err != nil {
		return "", fmt.Errorf("PublicLink: encrypt password: %w", err)
	}

	// Compute expiration (API expects seconds, fs.Duration is time.Duration i.e. nanoseconds).
	// fs.DurationOff is the "no expiry" sentinel (max int64 nanoseconds); it is
	// positive so we must explicitly exclude it from the > 0 check.
	var expirationDuration *int64
	if expire > 0 && expire != fs.DurationOff {
		secs := int64(time.Duration(expire).Seconds())
		expirationDuration = &secs
	}

	req := &protondriveapi.CreateShareURLReq{
		CreatorEmail:             f.addrEmail,
		Permissions:              shareURLReadPermissions,
		UrlPasswordSalt:          urlPasswordSaltB64,
		SharePasswordSalt:        sharePasswordSaltB64,
		SRPVerifier:              srpVerifierB64,
		SRPModulusID:             moduliResp.ModulusID,
		Flags:                    shareURLFlagRandomPassword,
		SharePassphraseKeyPacket: sharePassphraseKeyPacket,
		Password:                 armoredPassword,
		MaxAccesses:              0,
		ExpirationDuration:       expirationDuration,
	}

	var shareURL *protondriveapi.ShareURLData
	if err := f.pacer.Call(func() (bool, error) {
		var callErr error
		shareURL, callErr = f.client.CreateShareURL(ctx, shareInfo.shareID, req)
		return shouldRetry(ctx, callErr)
	}); err != nil {
		return "", fmt.Errorf("PublicLink: create share URL: %w", err)
	}

	// The public URL is the base URL + "#" + the plaintext password
	return shareURL.PublicURL + "#" + password, nil
}
