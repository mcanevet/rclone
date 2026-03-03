package protondrive

// auth.go contains authentication, credential management, and keyring
// bootstrapping helpers for the Proton Drive backend.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	srp "github.com/ProtonMail/go-srp"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/pquerna/otp/totp"

	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/fserrors"
)

// shouldRetry returns a boolean as to whether this err deserves to be
// retried.  It returns the err as a convenience
func shouldRetry(ctx context.Context, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	// api.RetryableError is produced by ProtonClient for 5xx responses and
	// transient block-storage errors. Treat it the same as fserrors.RetryError.
	var retryable *protondriveapi.RetryableError
	if errors.As(err, &retryable) {
		return true, err
	}
	return fserrors.ShouldRetry(err), err
}

func getConfigMap(m configmap.Mapper) (uid, accessToken, refreshToken, saltedKeyPass string, ok bool) {
	if accessToken, ok = m.Get(clientAccessTokenKey); !ok {
		return
	}

	if uid, ok = m.Get(clientUIDKey); !ok {
		return
	}

	if refreshToken, ok = m.Get(clientRefreshTokenKey); !ok {
		return
	}

	if saltedKeyPass, ok = m.Get(clientSaltedKeyPassKey); !ok {
		return
	}

	// empty strings are considered "ok" by m.Get, which is not true business-wise
	ok = accessToken != "" && uid != "" && refreshToken != "" && saltedKeyPass != ""

	return
}

func setConfigMap(m configmap.Mapper, uid, accessToken, refreshToken, saltedKeyPass string) {
	m.Set(clientUIDKey, uid)
	m.Set(clientAccessTokenKey, accessToken)
	m.Set(clientRefreshTokenKey, refreshToken)
	m.Set(clientSaltedKeyPassKey, saltedKeyPass)
}

func clearConfigMap(m configmap.Mapper) {
	setConfigMap(m, "", "", "", "")
}

// unlockKeyrings unlocks user and address keyrings using saltedKeyPass.
// It sets client.userKR, client.addrKRs, client.primaryKR and returns
// the primary address ID and email.
// user is pre-fetched by the caller to avoid a duplicate getUser API call.
func (f *Fs) unlockKeyrings(ctx context.Context, saltedKeyPass []byte, user *protondriveapi.User) (addrID, addrEmail string, err error) {
	// Build user keyring from all active user keys
	var userKeys []*pgpcrypto.Key
	for _, k := range user.Keys {
		if k.Active != 1 {
			continue
		}
		lockedKey, err := pgpcrypto.NewKeyFromArmored(k.PrivateKey)
		if err != nil {
			fs.Debugf(f, "skipping user key %s: %v", k.ID, err)
			continue
		}
		unlockedKey, err := lockedKey.Unlock(saltedKeyPass)
		if err != nil {
			fs.Debugf(f, "failed to unlock user key %s: %v", k.ID, err)
			continue
		}
		userKeys = append(userKeys, unlockedKey)
	}
	if len(userKeys) == 0 {
		return "", "", fmt.Errorf("unlockKeyrings: no user keys could be unlocked")
	}
	userKR, err := pgpcrypto.NewKeyRing(nil)
	if err != nil {
		return "", "", fmt.Errorf("unlockKeyrings: new user keyring: %w", err)
	}
	for _, k := range userKeys {
		if err := userKR.AddKey(k); err != nil {
			return "", "", fmt.Errorf("unlockKeyrings: add user key: %w", err)
		}
	}

	// Get addresses and unlock address keys
	var addresses []protondriveapi.Address
	if err = f.pacer.Call(func() (bool, error) {
		var e error
		addresses, e = f.client.GetAddresses(ctx)
		return shouldRetry(ctx, e)
	}); err != nil {
		return "", "", fmt.Errorf("unlockKeyrings: get addresses: %w", err)
	}
	addrKRs := make(map[string]*pgpcrypto.KeyRing)

	var primaryAddrID, primaryEmail string
	var primaryKR *pgpcrypto.KeyRing
	for _, addr := range addresses {
		if addr.Status != 1 {
			continue
		}
		addrKR, err := pgpcrypto.NewKeyRing(nil)
		if err != nil {
			continue
		}
		hasPrimaryKey := false
		for _, k := range addr.Keys {
			if k.Active != 1 {
				continue
			}
			lockedKey, err := pgpcrypto.NewKeyFromArmored(k.PrivateKey)
			if err != nil {
				fs.Debugf(f, "skipping addr key %s: %v", k.ID, err)
				continue
			}
			var unlockedKey *pgpcrypto.Key
			if k.Token != "" {
				// Token-based address key: decrypt the token with userKR to get the passphrase
				tokenMsg, err := pgpcrypto.NewPGPMessageFromArmored(k.Token)
				if err != nil {
					fs.Debugf(f, "skipping addr key %s: parse token: %v", k.ID, err)
					continue
				}
				tokenPlain, err := userKR.Decrypt(tokenMsg, nil, pgpcrypto.GetUnixTime())
				if err != nil {
					fs.Debugf(f, "skipping addr key %s: decrypt token: %v", k.ID, err)
					continue
				}
				unlockedKey, err = lockedKey.Unlock(tokenPlain.GetBinary())
				if err != nil {
					fs.Debugf(f, "skipping addr key %s: unlock with token: %v", k.ID, err)
					continue
				}
			} else {
				// Legacy: unlock directly with salted key pass
				unlockedKey, err = lockedKey.Unlock(saltedKeyPass)
				if err != nil {
					fs.Debugf(f, "skipping addr key %s: direct unlock: %v", k.ID, err)
					continue
				}
			}
			if err := addrKR.AddKey(unlockedKey); err != nil {
				fs.Debugf(f, "skipping addr key %s: add to keyring: %v", k.ID, err)
				continue
			}
			if k.Primary == 1 {
				hasPrimaryKey = true
			}
		}
		if addrKR.CountEntities() > 0 {
			addrKRs[addr.Email] = addrKR
			// Select this address as primary if it has a primary key and we
			// haven't found a primary address yet.  We check hasPrimaryKey
			// here (after the key loop) so we only set primaryAddrID for
			// addresses whose keys could actually be unlocked.
			if hasPrimaryKey && primaryAddrID == "" {
				primaryAddrID = addr.ID
				primaryEmail = addr.Email
				primaryKR = addrKR
			}
		}
	}

	// Fallback: pick the lexicographically first available address as primary
	// so that the selection is deterministic regardless of map iteration order.
	if primaryKR == nil {
		emails := make([]string, 0, len(addrKRs))
		for email := range addrKRs {
			emails = append(emails, email)
		}
		sort.Strings(emails)
		for _, email := range emails {
			primaryKR = addrKRs[email]
			for _, addr := range addresses {
				if addr.Email == email {
					primaryAddrID = addr.ID
					primaryEmail = email
					break
				}
			}
			break
		}
	}

	if primaryKR == nil {
		return "", "", fmt.Errorf("unlockKeyrings: no address keys could be unlocked")
	}

	// Commit all keyring state under the write lock.
	f.client.SetKeyrings(userKR, addrKRs, primaryKR)

	return primaryAddrID, primaryEmail, nil
}

// deriveSaltedKeyPass derives the salted key pass from the plain password.
// It fetches key salts, finds the salt for the primary user key, and derives
// the salted key pass using SRP's MailboxPassword, taking the last 31 bytes.
// user is pre-fetched by the caller to avoid a duplicate getUser API call.
func (f *Fs) deriveSaltedKeyPass(ctx context.Context, password string, user *protondriveapi.User) ([]byte, error) {
	// Find primary user key ID
	var primaryKeyID string
	for _, k := range user.Keys {
		if k.Primary == 1 {
			primaryKeyID = k.ID
			break
		}
	}
	if primaryKeyID == "" && len(user.Keys) > 0 {
		primaryKeyID = user.Keys[0].ID
	}

	var salts []protondriveapi.KeySalt
	if err := f.pacer.Call(func() (bool, error) {
		var e error
		salts, e = f.client.GetKeySalts(ctx)
		return shouldRetry(ctx, e)
	}); err != nil {
		return nil, fmt.Errorf("deriveSaltedKeyPass: get salts: %w", err)
	}

	var keySalt string
	for _, s := range salts {
		if s.ID == primaryKeyID {
			keySalt = s.KeySalt
			break
		}
	}

	if keySalt == "" {
		// No salt found: use password directly (some accounts have no salt)
		return []byte(password), nil
	}

	saltBytes, err := base64.StdEncoding.DecodeString(keySalt)
	if err != nil {
		return nil, fmt.Errorf("deriveSaltedKeyPass: decode salt: %w", err)
	}

	derived, err := srp.MailboxPassword([]byte(password), saltBytes)
	if err != nil {
		return nil, fmt.Errorf("deriveSaltedKeyPass: mailbox password: %w", err)
	}

	// Take the last 31 bytes as the salted key pass
	if len(derived) > 31 {
		derived = derived[len(derived)-31:]
	}
	return derived, nil
}

// bootstrapClient authenticates and populates all fields on f.client,
// then fetches the share/volume/rootLink metadata and sets f.volumeID,
// f.shareID, f.rootLinkID, f.addrID, f.addrEmail.
func (f *Fs) bootstrapClient(ctx context.Context) error {
	opt := &f.opt
	m := f.m

	// Try cached credentials first
	uid, accessToken, refreshToken, saltedKeyPassB64, hasCached := getConfigMap(m)

	if hasCached {
		fs.Debugf(f, "Has cached credentials, trying to reuse")
		saltedKeyPass, err := base64.StdEncoding.DecodeString(saltedKeyPassB64)
		if err != nil {
			fs.Debugf(f, "Could not decode cached salted key pass: %v", err)
			hasCached = false
		} else {
			// Restore token state
			f.client.SetTokens(uid, accessToken, refreshToken)

			var user *protondriveapi.User
			if err := f.pacer.Call(func() (bool, error) {
				var e error
				user, e = f.client.GetUser(ctx)
				return shouldRetry(ctx, e)
			}); err != nil {
				fs.Debugf(f, "Cached credential doesn't work, falling back to login: %v", err)
				hasCached = false
				clearConfigMap(m)
			} else {
				addrID, addrEmail, err := f.unlockKeyrings(ctx, saltedKeyPass, user)
				if err != nil {
					fs.Debugf(f, "Cached credential doesn't work, falling back to login: %v", err)
					hasCached = false
					clearConfigMap(m)
				} else {
					f.addrID = addrID
					f.addrEmail = addrEmail
					fs.Debugf(f, "Used cached credential to initialize the ProtonDrive API")
				}
			}
		}
	}

	if !hasCached {
		// Full SRP login
		fs.Debugf(f, "Using username and password to log in")
		password := f.password
		twoFA := opt.TwoFA
		if twoFA == "" && f.otpSecretKey != "" {
			code, err := totp.GenerateCode(f.otpSecretKey, time.Now())
			if err != nil {
				return fmt.Errorf("bootstrapClient: generate 2FA code: %w", err)
			}
			twoFA = code
		}

		var authResp *protondriveapi.Auth
		if err := f.pacer.Call(func() (bool, error) {
			var e error
			authResp, e = f.client.Login(ctx, opt.Username, password)
			return shouldRetry(ctx, e)
		}); err != nil {
			return fmt.Errorf("bootstrapClient: login: %w", err)
		}

		if authResp.TwoFA.Enabled > 0 {
			if twoFA == "" {
				return fmt.Errorf("bootstrapClient: 2FA required but no code provided")
			}
			if err := f.pacer.Call(func() (bool, error) {
				e := f.client.Submit2FA(ctx, twoFA)
				return shouldRetry(ctx, e)
			}); err != nil {
				return fmt.Errorf("bootstrapClient: 2FA: %w", err)
			}
		}

		// Derive salted key pass (fetch user once; pass to both deriveSaltedKeyPass and unlockKeyrings)
		keyPass := password
		if authResp.PasswordMode == 2 && f.mailboxPassword != "" {
			keyPass = f.mailboxPassword
		}

		var user *protondriveapi.User
		if err := f.pacer.Call(func() (bool, error) {
			var e error
			user, e = f.client.GetUser(ctx)
			return shouldRetry(ctx, e)
		}); err != nil {
			return fmt.Errorf("bootstrapClient: get user: %w", err)
		}

		saltedKeyPass, err := f.deriveSaltedKeyPass(ctx, keyPass, user)
		if err != nil {
			return fmt.Errorf("bootstrapClient: derive salted key pass: %w", err)
		}

		addrID, addrEmail, err := f.unlockKeyrings(ctx, saltedKeyPass, user)
		if err != nil {
			return fmt.Errorf("bootstrapClient: unlock keyrings: %w", err)
		}

		// Zero out the revealed credentials now that all downstream calls have
		// consumed them successfully.
		f.password = ""
		f.mailboxPassword = ""
		f.otpSecretKey = ""

		f.addrID = addrID
		f.addrEmail = addrEmail

		// Save credentials
		saltedKeyPassB64 = base64.StdEncoding.EncodeToString(saltedKeyPass)
		setConfigMap(m, f.client.UID(), f.client.AccessToken(), f.client.RefreshToken(), saltedKeyPassB64)
		fs.Debugf(f, "Used username and password to initialize the ProtonDrive API")
	}

	// Bootstrap share / volume / root link
	var filesShare *protondriveapi.FilesShareResp
	if err := f.pacer.Call(func() (bool, error) {
		var e error
		filesShare, e = f.client.GetFilesShare(ctx)
		return shouldRetry(ctx, e)
	}); err != nil {
		return fmt.Errorf("bootstrapClient: get files share: %w", err)
	}
	f.shareID = filesShare.Share.ShareID
	f.volumeID = filesShare.Volume.VolumeID
	f.rootLinkID = filesShare.Link.Link.LinkID

	// Unlock the share/root link keyring and cache it
	if err := f.unlockShareKeyring(ctx, filesShare); err != nil {
		return fmt.Errorf("bootstrapClient: unlock share keyring: %w", err)
	}

	return nil
}

// unlockShareKeyring unlocks the share key and the root link's own node keyring,
// then caches both so that:
//   - shareKR is used as the parent keyring when unlocking the root link's children
//   - rootNodeKR is used when decrypting the root link's own NodeHashKey
func (f *Fs) unlockShareKeyring(ctx context.Context, filesShare *protondriveapi.FilesShareResp) error {
	addrKR := f.client.GetPrimaryKR()
	if addrKR == nil {
		return fmt.Errorf("unlockShareKeyring: no primary address keyring")
	}
	share := &filesShare.Share

	// Decrypt share passphrase using the address keyring
	encMsg, err := pgpcrypto.NewPGPMessageFromArmored(share.Passphrase)
	if err != nil {
		return fmt.Errorf("unlockShareKeyring: parse passphrase: %w", err)
	}
	decMsg, err := addrKR.Decrypt(encMsg, nil, pgpcrypto.GetUnixTime())
	if err != nil {
		// Try with signature verification against address keyring
		decMsg, err = addrKR.Decrypt(encMsg, addrKR, pgpcrypto.GetUnixTime())
		if err != nil {
			return fmt.Errorf("unlockShareKeyring: decrypt passphrase: %w", err)
		}
	}

	// Unlock share key
	shareLockedKey, err := pgpcrypto.NewKeyFromArmored(share.Key)
	if err != nil {
		return fmt.Errorf("unlockShareKeyring: parse share key: %w", err)
	}
	shareUnlockedKey, err := shareLockedKey.Unlock(decMsg.GetBinary())
	if err != nil {
		return fmt.Errorf("unlockShareKeyring: unlock share key: %w", err)
	}
	shareKR, err := pgpcrypto.NewKeyRing(shareUnlockedKey)
	if err != nil {
		return fmt.Errorf("unlockShareKeyring: new share keyring: %w", err)
	}

	// Store the share keyring on f so callers can use it as the parent
	// keyring for the root link (whose NodePassphrase is encrypted to shareKR).
	f.shareKR = shareKR

	// Fetch the root link to unlock its own node key.
	// The share key (shareKR) is used only to decrypt the root link's
	// NodePassphrase. After that, all operations use the root node keyring.
	// The root link's NodeHashKey is encrypted to the root node key (not
	// the share key), so we must derive the root node keyring here.
	rootLinkID := filesShare.Link.Link.LinkID
	var rootLinks []protondriveapi.LinkWrapper
	if pacerErr := f.pacer.Call(func() (bool, error) {
		var callErr error
		rootLinks, callErr = f.client.BatchGetLinks(ctx, f.volumeID, []string{rootLinkID})
		return shouldRetry(ctx, callErr)
	}); pacerErr != nil {
		return fmt.Errorf("unlockShareKeyring: fetch root link: %w", pacerErr)
	}
	if len(rootLinks) == 0 {
		// Fall back to shareKR; operations that need the root hash key will fail,
		// but auth/listing still works.
		fs.Debugf(f, "unlockShareKeyring: could not fetch root link; falling back to shareKR")
		f.linkKRCache.Add(rootLinkID, shareKR)
		return nil
	}
	rootLink := rootLinks[0]
	rootNodeKR, err := protondriveapi.UnlockNodeKey(
		rootLink.Link.NodeKey,
		rootLink.Link.NodePassphrase,
		rootLink.Link.NodePassphraseSignature,
		shareKR,
		addrKR,
	)
	if errors.Is(err, protondriveapi.ErrPassphraseSignatureMismatch) {
		fs.Debugf(f, "unlockShareKeyring: root node key: %v", err)
	} else if err != nil {
		return fmt.Errorf("unlockShareKeyring: unlock root node key: %w", err)
	}

	// Cache the root node KR as the root link's keyring.
	// Children of the root have their NodePassphrase encrypted to the root node
	// key (not the share key), so this is correct for unlockLink as well.
	f.linkKRCache.Add(rootLinkID, rootNodeKR)

	return nil
}
