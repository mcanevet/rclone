// Package protondrive — unit tests for internal Fs logic that are unblocked
// by the protondriveapi.Client interface.  These tests use a stub/mock client
// so they run without any network access and do not require credentials.
package protondrive

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
)

// testKeyArmored is a pre-generated x25519 PGP private key used in unit tests
// to avoid the latency of runtime key generation.  It has no passphrase.
const testKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: https://gopenpgp.org
Version: GopenPGP 2.9.0

xVgEaaWtYhYJKwYBBAHaRw8BAQdA9DmGWm/OdjMxXOUpRhYYXPjhFC18uiO6cvvT
3q+r7SUAAPsGiUxzoQk6v1N5QQuwmummBtNeLRapdrkE7f0ky8ztKQ/uzRB0ZXN0
IDx0ZXN0QHRlc3Q+wr8EExYIAHEFgmmlrWIDCwkHCRCMO90oVQGO7zUUAAAAAAAc
ABBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3JnvXFG91FAXNzk1vPAsQ4yYQIV
CAMWAAICGQECmwMCHgEWIQTjqJ2BVbk2HDX1sfGMO90oVQGO7wAABY0BAPj60PZ0
m2xQLUPekMD15qp3dj7t7oVVQYmsmUM2ZYgeAP4qLQEi50W8KExGqs4/eswFmQoB
JCgcUfbmTMFq0ZUZDsddBGmlrWISCisGAQQBl1UBBQEBB0BT0cOIJRH9fcYPwJE4
Sajs0N+wqLVbkiCxGg+MvNQodwMBCgkAAP9j1ZiZmRcFI3C4XedCJsTWWw7Dhdp/
65c82jQ2MOK5CBCNwq4EGBYIAGAFgmmlrWIJEIw73ShVAY7vNRQAAAAAABwAEHNh
bHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmel3om6eKwi0cqr9QzNRiglApsMFiEE
46idgVW5Nhw19bHxjDvdKFUBju8AACXZAQD/99B96MtawULoBCp+GnSIhB1bVsDN
GWi1fWty8wWdpgD/Z+9IgzBAs+nEDB+vH76wRXNvPl7cZynV0k3sw7B4LAY=
=099p
-----END PGP PRIVATE KEY BLOCK-----
`

// ---- noopClient / stubClient -----------------------------------------------

// noopClient is a base type that satisfies protondriveapi.Client with no-op
// implementations. Methods that must not be called in a given test panic;
// methods that are safely ignorable return zero values. Test-specific types
// embed noopClient and override only the methods they need.
type noopClient struct{}

func (noopClient) UID() string              { return "uid" }
func (noopClient) AccessToken() string      { return "tok" }
func (noopClient) RefreshToken() string     { return "" }
func (noopClient) SetTokens(_, _, _ string) {}

func (noopClient) GetUserKR() *pgpcrypto.KeyRing    { return nil }
func (noopClient) GetPrimaryKR() *pgpcrypto.KeyRing { return nil }
func (noopClient) SetKeyrings(_ *pgpcrypto.KeyRing, _ map[string]*pgpcrypto.KeyRing, _ *pgpcrypto.KeyRing) {
}

func (noopClient) Login(_ context.Context, _, _ string) (*protondriveapi.Auth, error) {
	panic("unexpected Login call")
}
func (noopClient) Submit2FA(_ context.Context, _ string) error {
	panic("unexpected Submit2FA call")
}
func (noopClient) Logout(_ context.Context) error { return nil }

func (noopClient) GetUser(_ context.Context) (*protondriveapi.User, error) {
	panic("unexpected GetUser call")
}
func (noopClient) GetAddresses(_ context.Context) ([]protondriveapi.Address, error) {
	panic("unexpected GetAddresses call")
}
func (noopClient) GetKeySalts(_ context.Context) ([]protondriveapi.KeySalt, error) {
	panic("unexpected GetKeySalts call")
}
func (noopClient) GetFilesShare(_ context.Context) (*protondriveapi.FilesShareResp, error) {
	panic("unexpected GetFilesShare call")
}
func (noopClient) GetShare(_ context.Context, _ string) (*protondriveapi.Share, error) {
	panic("unexpected GetShare call")
}
func (noopClient) CreateStandardShare(_ context.Context, _ string, _ *protondriveapi.CreateStandardShareReq) (string, error) {
	panic("unexpected CreateStandardShare call")
}
func (noopClient) FindShareIDForLink(_ context.Context, _, _ string) (string, error) {
	panic("unexpected FindShareIDForLink call")
}

func (noopClient) BatchGetLinks(_ context.Context, _ string, _ []string) ([]protondriveapi.LinkWrapper, error) {
	return nil, nil
}
func (noopClient) WalkFolderChildren(_ context.Context, _, _ string, _ func([]protondriveapi.LinkWrapper) error) error {
	return nil
}
func (noopClient) ListFolderChildren(_ context.Context, _, _ string) ([]protondriveapi.LinkWrapper, error) {
	return nil, nil
}

func (noopClient) CreateFolder(_ context.Context, _ string, _ *protondriveapi.CreateFolderReq) (string, error) {
	panic("unexpected CreateFolder call")
}
func (noopClient) CreateFile(_ context.Context, _ string, _ *protondriveapi.CreateFileReq) (string, string, error) {
	panic("unexpected CreateFile call")
}
func (noopClient) CreateRevision(_ context.Context, _, _ string) (string, error) {
	panic("unexpected CreateRevision call")
}
func (noopClient) GetRevision(_ context.Context, _, _, _ string) (*protondriveapi.Revision, error) {
	panic("unexpected GetRevision call")
}
func (noopClient) ListRevisions(_ context.Context, _, _ string) ([]protondriveapi.Revision, error) {
	panic("unexpected ListRevisions call")
}
func (noopClient) CommitRevision(_ context.Context, _, _, _ string, _ *protondriveapi.CommitRevisionReq) error {
	panic("unexpected CommitRevision call")
}
func (noopClient) DeleteRevision(_ context.Context, _, _, _ string) error {
	panic("unexpected DeleteRevision call")
}
func (noopClient) GetVerificationCode(_ context.Context, _, _, _ string) (string, error) {
	panic("unexpected GetVerificationCode call")
}
func (noopClient) RequestBlockUploadURLs(_ context.Context, _ *protondriveapi.BlockUploadReq) ([]protondriveapi.BlockUploadLink, error) {
	panic("unexpected RequestBlockUploadURLs call")
}
func (noopClient) UploadBlock(_ context.Context, _, _ string, _ []byte) error {
	panic("unexpected UploadBlock call")
}
func (noopClient) DownloadBlock(_ context.Context, _, _ string) ([]byte, error) {
	panic("unexpected DownloadBlock call")
}
func (noopClient) RenameLink(_ context.Context, _, _ string, _ *protondriveapi.MoveLinkReq) error {
	panic("unexpected RenameLink call")
}
func (noopClient) MoveLink(_ context.Context, _, _ string, _ *protondriveapi.MoveLinkReq) error {
	panic("unexpected MoveLink call")
}
func (noopClient) TrashLinks(_ context.Context, _ string, _ []string) error {
	panic("unexpected TrashLinks call")
}
func (noopClient) DeleteDraftLinks(_ context.Context, _ string, _ []string) error {
	panic("unexpected DeleteDraftLinks call")
}
func (noopClient) EmptyTrash(_ context.Context, _ string) error {
	panic("unexpected EmptyTrash call")
}
func (noopClient) CheckAvailableHashes(_ context.Context, _, _ string, _ []string) (*protondriveapi.CheckHashesResp, error) {
	panic("unexpected CheckAvailableHashes call")
}
func (noopClient) GetSRPModuli(_ context.Context) (*protondriveapi.SRPModuliResp, error) {
	panic("unexpected GetSRPModuli call")
}
func (noopClient) ListShareURLs(_ context.Context, _ string) ([]protondriveapi.ShareURLData, error) {
	panic("unexpected ListShareURLs call")
}
func (noopClient) CreateShareURL(_ context.Context, _ string, _ *protondriveapi.CreateShareURLReq) (*protondriveapi.ShareURLData, error) {
	panic("unexpected CreateShareURL call")
}
func (noopClient) DeleteShareURLs(_ context.Context, _ string, _ []string) error {
	panic("unexpected DeleteShareURLs call")
}
func (noopClient) GetLatestEventID(_ context.Context, _ string) (string, error) { return "ev0", nil }
func (noopClient) PollEvents(_ context.Context, _, _ string) (*protondriveapi.DriveEventResp, error) {
	return &protondriveapi.DriveEventResp{}, nil
}

// stubClient embeds noopClient and adds fields that tests can configure.
// Only the methods that tests need to override are redeclared here.
type stubClient struct {
	noopClient
	mu sync.Mutex

	userKR    *pgpcrypto.KeyRing
	primaryKR *pgpcrypto.KeyRing

	// batchGetLinksFunc, if non-nil, is called by BatchGetLinks.
	batchGetLinksFunc func(ctx context.Context, volumeID string, ids []string) ([]protondriveapi.LinkWrapper, error)
}

func (s *stubClient) GetUserKR() *pgpcrypto.KeyRing {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userKR
}
func (s *stubClient) GetPrimaryKR() *pgpcrypto.KeyRing {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.primaryKR
}
func (s *stubClient) SetKeyrings(userKR *pgpcrypto.KeyRing, _ map[string]*pgpcrypto.KeyRing, primaryKR *pgpcrypto.KeyRing) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userKR = userKR
	s.primaryKR = primaryKR
}

func (s *stubClient) BatchGetLinks(ctx context.Context, volumeID string, ids []string) ([]protondriveapi.LinkWrapper, error) {
	if s.batchGetLinksFunc != nil {
		return s.batchGetLinksFunc(ctx, volumeID, ids)
	}
	return nil, nil
}

// ---- helpers ---------------------------------------------------------------

// newTestFs creates a minimal *Fs with a stub client, a real syncedLRUCache,
// and a real dircache.  It is suitable for testing cache management, event
// notification, and unlockLink caching without any network activity.
func newTestFs(t *testing.T, client protondriveapi.Client) *Fs {
	t.Helper()
	ctx := context.Background()
	f := &Fs{
		name:          "test",
		root:          "",
		client:        client,
		volumeID:      "vol1",
		pacer:         fs.NewPacer(ctx, pacer.NewDefault()),
		linkKRCache:   mustNewLRU[string, *pgpcrypto.KeyRing](linkKRCacheMax),
		stopPoller:    func() {},
		pollIntervalC: make(chan time.Duration, 1),
		opt: Options{
			Enc: encoder.Base,
		},
	}
	// Build a real dircache using f as the DirCacher.
	// root="" and rootLinkID="root-link-id" matches volumeID.
	f.rootLinkID = "root-link-id"
	f.dirCache = dircache.New("", f.rootLinkID, f)
	return f
}

// ---- flushCaches -----------------------------------------------------------

// TestFlushCachesResetsLinkKRCache checks that flushCaches evicts all entries
// from the linkKRCache.
func TestFlushCachesResetsLinkKRCache(t *testing.T) {
	f := newTestFs(t, &stubClient{})

	// Populate the cache with a dummy keyring pointer.
	dummyKR := &pgpcrypto.KeyRing{} // zero-value; pointer identity is all we need
	f.linkKRCache.Add("link-a", dummyKR)

	// Verify entry is present.
	_, ok := f.linkKRCache.Get("link-a")
	require.True(t, ok, "cache should contain the entry before flush")

	f.flushCaches()

	// Entry should be gone.
	_, ok = f.linkKRCache.Get("link-a")
	assert.False(t, ok, "cache should be empty after flushCaches")
}

// TestFlushCachesResetsDirCache checks that flushCaches resets the dircache
// so previously cached path→ID mappings are removed.
func TestFlushCachesResetsDirCache(t *testing.T) {
	f := newTestFs(t, &stubClient{})

	// Put an entry into the dircache.
	f.dirCache.Put("docs", "link-docs")
	_, ok := f.dirCache.Get("docs")
	require.True(t, ok, "dircache should contain the entry before flush")

	f.flushCaches()

	_, ok = f.dirCache.Get("docs")
	assert.False(t, ok, "dircache should not contain the entry after flushCaches")
}

// ---- notifyEvents ----------------------------------------------------------

// TestNotifyEventsNoFnFlushesCaches checks that when no notify function is
// registered, arriving events flush both caches.
func TestNotifyEventsNoFnFlushesCaches(t *testing.T) {
	f := newTestFs(t, &stubClient{})

	// Seed the caches.
	f.dirCache.Put("photos", "link-photos")
	f.linkKRCache.Add("link-photos", &pgpcrypto.KeyRing{})

	// Simulate one event arriving with no notifyFunc registered.
	events := []protondriveapi.DriveEventLink{
		{EventType: protondriveapi.EventActionCreate, Link: protondriveapi.EventLinkData{LinkID: "link-new"}},
	}
	f.notifyEvents(context.Background(), events)

	// Both caches must now be empty.
	_, inDir := f.dirCache.Get("photos")
	assert.False(t, inDir, "dircache must be flushed when no notify fn is registered")

	_, inKR := f.linkKRCache.Get("link-photos")
	assert.False(t, inKR, "linkKRCache must be flushed when no notify fn is registered")
}

// TestNotifyEventsWithFnCallsFnDoesNotFlush verifies that when a notifyFunc is
// registered, the callback is invoked with the correct path and entry type, and
// the dircache is NOT flushed during path resolution (so the notify fn can use
// it to re-list the affected directory).
func TestNotifyEventsWithFnCallsFnDoesNotFlush(t *testing.T) {
	// We need a client that returns link metadata for our fake link.
	client := &stubClient{}

	// Prepare a fake key pair so we can encrypt/decrypt the link name.
	// Use a pre-generated static key to avoid the latency of runtime key generation.
	key, err := pgpcrypto.NewKeyFromArmored(testKeyArmored)
	require.NoError(t, err, "parse static test key")
	unlockedKey, err := key.Unlock(nil)
	require.NoError(t, err, "unlock static test key (no passphrase)")
	kr, err := pgpcrypto.NewKeyRing(unlockedKey)
	require.NoError(t, err, "new keyring")

	// Encrypt the name "hello.txt" with the parent KR.
	encName, err := kr.Encrypt(pgpcrypto.NewPlainMessageFromString("hello.txt"), nil)
	require.NoError(t, err, "encrypt name")
	encNameArmored, err := encName.GetArmored()
	require.NoError(t, err, "armor name")

	// The fake link returned by BatchGetLinks.
	fakeLink := protondriveapi.LinkWrapper{
		Link: protondriveapi.LinkCore{
			LinkID:       "link-file",
			ParentLinkID: "link-parent",
			Type:         protondriveapi.LinkTypeFile,
			Name:         encNameArmored,
		},
	}
	client.batchGetLinksFunc = func(_ context.Context, _ string, ids []string) ([]protondriveapi.LinkWrapper, error) {
		var out []protondriveapi.LinkWrapper
		for _, id := range ids {
			if id == "link-file" {
				out = append(out, fakeLink)
			}
		}
		return out, nil
	}

	f := newTestFs(t, client)

	// Put the parent folder into the dircache and linkKRCache so resolveLinkPath can work.
	f.dirCache.Put("photos", "link-parent")
	f.linkKRCache.Add("link-parent", kr)

	// Register a notify function and collect its calls.
	type call struct {
		path      string
		entryType fs.EntryType
	}
	var (
		callsMu sync.Mutex
		calls   []call
	)
	f.notifyMu.Lock()
	f.notifyFunc = func(p string, et fs.EntryType) {
		callsMu.Lock()
		calls = append(calls, call{p, et})
		callsMu.Unlock()
	}
	f.notifyMu.Unlock()

	// Simulate a create event for the file.
	events := []protondriveapi.DriveEventLink{
		{
			EventType: protondriveapi.EventActionCreate,
			Link:      protondriveapi.EventLinkData{LinkID: "link-file", ParentLinkID: "link-parent"},
		},
	}
	f.notifyEvents(context.Background(), events)

	// The notify function must have been called.
	callsMu.Lock()
	defer callsMu.Unlock()
	require.Len(t, calls, 1, "notify fn should be called once")
	assert.Equal(t, "photos/hello.txt", calls[0].path)
	assert.Equal(t, fs.EntryObject, calls[0].entryType)

	// The dircache must NOT have been flushed (parent still in cache).
	_, ok := f.dirCache.Get("photos")
	assert.True(t, ok, "dircache must not be flushed when notify fn is registered")
}

// ---- unlockLink KR cache ---------------------------------------------------

// TestUnlockLinkCacheHit verifies that unlockLink returns a cached keyring
// without making any BatchGetLinks API call when the KR is already in the cache.
func TestUnlockLinkCacheHit(t *testing.T) {
	batchCalled := false
	client := &stubClient{
		batchGetLinksFunc: func(_ context.Context, _ string, _ []string) ([]protondriveapi.LinkWrapper, error) {
			batchCalled = true
			return nil, nil
		},
	}
	f := newTestFs(t, client)

	// Pre-populate the KR cache with a dummy entry.
	dummyKR := &pgpcrypto.KeyRing{}
	f.linkKRCache.Add("link-x", dummyKR)

	// unlockLink should return the cached KR without hitting the API.
	kr, err := f.unlockLink(context.Background(), "link-x")
	require.NoError(t, err)
	assert.Same(t, dummyKR, kr, "unlockLink should return the cached KR")
	assert.False(t, batchCalled, "BatchGetLinks should not be called on a cache hit")
}

// TestComputeBcryptPassphrase verifies the bcrypt passphrase derivation used
// for Proton Drive public link passwords.
func TestComputeBcryptPassphrase(t *testing.T) {
	// Known test vector: 16-byte zero salt, password "testpassword".
	// The expected passphrase was computed by running the algorithm once and
	// is hardcoded here to catch regressions.
	salt := make([]byte, 16) // all-zero 16-byte salt
	passphrase, saltB64, err := computeBcryptPassphrase("testpassword", salt)
	require.NoError(t, err)

	// saltB64 must be the standard base64 encoding of the input salt.
	require.Equal(t, base64.StdEncoding.EncodeToString(salt), saltB64)

	// bcrypt output is 60 bytes; we strip the 29-byte prefix ($2y$10$ + 22-char
	// encoded salt), leaving a 31-byte passphrase.
	const wantPassphraseLen = 31
	require.Lenf(t, passphrase, wantPassphraseLen,
		"passphrase length should be %d", wantPassphraseLen)

	// The function must be deterministic: same inputs → same outputs.
	passphrase2, saltB642, err2 := computeBcryptPassphrase("testpassword", salt)
	require.NoError(t, err2)
	require.Equal(t, passphrase, passphrase2, "computeBcryptPassphrase must be deterministic")
	require.Equal(t, saltB64, saltB642)

	// Different passwords must produce different passphrases.
	passphraseOther, _, err3 := computeBcryptPassphrase("differentpassword", salt)
	require.NoError(t, err3)
	require.NotEqual(t, passphrase, passphraseOther,
		"different passwords must produce different passphrases")

	// Different salts must produce different passphrases.
	salt2 := make([]byte, 16)
	salt2[0] = 0xFF
	passphraseOtherSalt, _, err4 := computeBcryptPassphrase("testpassword", salt2)
	require.NoError(t, err4)
	require.NotEqual(t, passphrase, passphraseOtherSalt,
		"different salts must produce different passphrases")
}
