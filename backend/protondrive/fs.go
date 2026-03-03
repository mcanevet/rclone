// Package protondrive implements the Proton Drive backend
package protondrive

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"

	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
)

/*
- dirCache operates on relative path to root
- path sanitization
	- rule of thumb: sanitize before use, but store things as-is
	- the paths cached in dirCache are after sanitizing
	- the remote/dir passed in aren't, and are stored as-is
*/

const (
	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2 // bigger for slower decay, exponential

	clientUIDKey           = "client_uid"
	clientAccessTokenKey   = "client_access_token"
	clientRefreshTokenKey  = "client_refresh_token"
	clientSaltedKeyPassKey = "client_salted_key_pass"

	eventPollInterval = 30 * time.Second

	// linkKRCacheMax is the maximum number of node keyrings held in the LRU
	// cache.  Each entry is a small *pgpcrypto.KeyRing (one or more ECC keys).
	// 2048 is generous for any realistic directory tree while keeping the
	// memory footprint bounded during long-running mounts.
	linkKRCacheMax = 2048
)

var (
	errCanNotUploadFileWithUnknownSize = errors.New("proton Drive can't upload files with unknown size")
	errCanNotPurgeRootDirectory        = errors.New("can't purge root directory")
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "protondrive",
		Description: "Proton Drive",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "username",
			Help:     `The username of your proton account`,
			Required: true,
		}, {
			Name:       "password",
			Help:       "The password of your proton account.",
			Required:   true,
			IsPassword: true,
		}, {
			Name: "mailbox_password",
			Help: `The mailbox password of your two-password proton account.

For more information regarding the mailbox password, please check the 
following official knowledge base article: 
https://proton.me/support/the-difference-between-the-mailbox-password-and-login-password
`,
			IsPassword: true,
			Advanced:   true,
		}, {
			Name: "2fa",
			Help: `The 2FA code

The value can also be provided with --protondrive-2fa=000000

The 2FA code of your proton drive account if the account is set up with 
two-factor authentication`,
			Required: false,
		}, {
			Name: "otp_secret_key",
			Help: `The OTP secret key

The value can also be provided with --protondrive-otp-secret-key=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567

The OTP secret key of your proton drive account if the account is set up with 
two-factor authentication`,
			Required:   false,
			Sensitive:  true,
			IsPassword: true,
		}, {
			Name:      clientUIDKey,
			Help:      "Client uid key (internal use only)",
			Required:  false,
			Advanced:  true,
			Sensitive: true,
			Hide:      fs.OptionHideBoth,
		}, {
			Name:      clientAccessTokenKey,
			Help:      "Client access token key (internal use only)",
			Required:  false,
			Advanced:  true,
			Sensitive: true,
			Hide:      fs.OptionHideBoth,
		}, {
			Name:      clientRefreshTokenKey,
			Help:      "Client refresh token key (internal use only)",
			Required:  false,
			Advanced:  true,
			Sensitive: true,
			Hide:      fs.OptionHideBoth,
		}, {
			Name:      clientSaltedKeyPassKey,
			Help:      "Client salted key pass key (internal use only)",
			Required:  false,
			Advanced:  true,
			Sensitive: true,
			Hide:      fs.OptionHideBoth,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default: (encoder.Base |
				encoder.EncodeInvalidUtf8 |
				encoder.EncodeLeftSpace |
				encoder.EncodeRightSpace),
		}, {
			Name: "original_file_size",
			Help: `Return the file size before encryption
			
The size of the encrypted file will be different from (bigger than) the 
original file size. Unless there is a reason to return the file size 
after encryption is performed, otherwise, set this option to true, as 
features like Open() which will need to be supplied with original content 
size, will fail to operate properly`,
			Advanced: true,
			Default:  true,
		}, {
			Name: "app_version",
			Help: `The app version string 

The app version string indicates the client that is currently performing 
the API request. This information is required and will be sent with every 
API request.`,
			Advanced: true,
			Default:  "external-drive-rclone@1.0.0",
		}, {
			Name: "replace_existing_draft",
			Help: `Create a new revision when filename conflict is detected

When a file upload is cancelled or failed before completion, a draft will be 
created and the subsequent upload of the same file to the same location will be 
reported as a conflict.

The value can also be set by --protondrive-replace-existing-draft=true

If the option is set to true, the draft will be replaced and then the upload 
operation will restart. If there are other clients also uploading at the same 
file location at the same time, the behavior is currently unknown. Need to set 
to true for integration tests.
If the option is set to false, an error "a draft exist - usually this means a 
file is being uploaded at another client, or, there was a failed upload attempt" 
will be returned, and no upload will happen.`,
			Advanced: true,
			Default:  false,
		}, {
			Name:     "api_url",
			Help:     `Override the Proton API base URL (for testing)`,
			Advanced: true,
			Default:  "",
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	Username        string `config:"username"`
	Password        string `config:"password"`
	MailboxPassword string `config:"mailbox_password"`
	TwoFA           string `config:"2fa"`
	OtpSecretKey    string `config:"otp_secret_key"`

	// advanced
	Enc                  encoder.MultiEncoder `config:"encoding"`
	ReportOriginalSize   bool                 `config:"original_file_size"`
	AppVersion           string               `config:"app_version"`
	ReplaceExistingDraft bool                 `config:"replace_existing_draft"`
	APIURL               string               `config:"api_url"`
}

// Fs represents a remote proton drive
type Fs struct {
	name     string             // name of this remote
	root     string             // the path we are working on.
	opt      Options            // parsed config options
	ci       *fs.ConfigInfo     // global config
	features *fs.Features       // optional features
	pacer    *fs.Pacer          // pacer for API calls
	dirCache *dircache.DirCache // Map of directory path to directory id
	m        configmap.Mapper   // config map for credential persistence
	// ctx is derived from the NewFs context via context.WithoutCancel so that
	// background operations (DirCacheFlush, event poller) are not cancelled when
	// the caller's request context expires.  It still inherits values (e.g. the
	// rclone config info) from the original context.
	ctx context.Context

	// Revealed (plaintext) credentials used only during bootstrapClient.
	// They are zeroed out by bootstrapClient as soon as the SRP login
	// completes so that plaintext passwords are not retained in memory for
	// the lifetime of the Fs.
	password        string
	mailboxPassword string
	otpSecretKey    string

	client     protondriveapi.Client // REST API client
	volumeID   string                // volume ID for the user's main drive
	shareID    string                // share ID for the main files share
	rootLinkID string                // link ID of the share root folder
	shareKR    *pgpcrypto.KeyRing    // share keyring (parent of root link)
	addrID     string                // primary address ID (for signing)
	addrEmail  string                // primary address email

	// linkKRCache caches unlocked node keyrings by linkID.
	// It is bounded to linkKRCacheMax entries to prevent unbounded growth
	// during long-running mount sessions.  The mutex is bundled inside the
	// cache; callers do not need an external lock.
	linkKRCache *lru.Cache[string, *pgpcrypto.KeyRing]

	stopPoller    func()             // cancels the event poller's context
	pollIntervalC chan time.Duration // send a new interval to the poller

	notifyMu   sync.Mutex                 // protects notifyFunc
	notifyFunc func(string, fs.EntryType) // optional ChangeNotify callback; nil if not registered
}

// Object describes an object
type Object struct {
	fs           *Fs       // what this object is part of
	remote       string    // The remote path (relative to the fs.root)
	size         int64     // size of the object (on server, after encryption)
	originalSize *int64    // size of the object (after decryption)
	digests      *string   // object original content SHA1
	blockSizes   []int64   // the block sizes of the encrypted file
	modTime      time.Time // modification time of the object
	createdTime  time.Time // creation time of the object
	id           string    // ID of the object (linkID)
	parentID     string    // ID of the parent folder (parentLinkID)
	mimetype     string    // mimetype of the file
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.opt.Enc.ToStandardPath(f.root)
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("proton drive root '%s'", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// run all the dir/remote through this
func (f *Fs) sanitizePath(p string) string {
	p = path.Clean(p)
	if p == "." || p == "/" {
		return ""
	}

	return f.opt.Enc.FromStandardPath(p)
}

// newHTTPClientFromFs creates an *http.Client configured with rclone's global
// HTTP settings (proxy, TLS, timeouts). This is the only rclone-specific
// dependency needed to construct a protonClient.
func newHTTPClientFromFs(ctx context.Context) *http.Client {
	return fshttp.NewClient(ctx)
}

// mustNewLRU creates a new LRU cache of the given size, panicking if size <= 0.
func mustNewLRU[K comparable, V any](size int) *lru.Cache[K, V] {
	c, err := lru.New[K, V](size)
	if err != nil {
		panic(err)
	}
	return c
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	// Reveal obscured credentials into local variables so that the plaintext
	// passwords are never stored in opt (and therefore not in f.opt).
	var password, mailboxPassword, otpSecretKey string
	if opt.Password != "" {
		password, err = obscure.Reveal(opt.Password)
		if err != nil {
			return nil, fmt.Errorf("couldn't decrypt password: %w", err)
		}
	}
	if opt.MailboxPassword != "" {
		mailboxPassword, err = obscure.Reveal(opt.MailboxPassword)
		if err != nil {
			return nil, fmt.Errorf("couldn't decrypt mailbox password: %w", err)
		}
	}
	if opt.OtpSecretKey != "" {
		otpSecretKey, err = obscure.Reveal(opt.OtpSecretKey)
		if err != nil {
			return nil, fmt.Errorf("couldn't decrypt OtpSecretKey: %w", err)
		}
	}

	ci := fs.GetConfig(ctx)

	root = strings.Trim(root, "/")

	f := &Fs{
		name:            name,
		root:            root,
		opt:             *opt,
		ci:              ci,
		m:               m,
		ctx:             context.WithoutCancel(ctx),
		pacer:           fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
		linkKRCache:     mustNewLRU[string, *pgpcrypto.KeyRing](linkKRCacheMax),
		stopPoller:      func() {}, // replaced by startEventPoller
		pollIntervalC:   make(chan time.Duration, 1),
		password:        password,
		mailboxPassword: mailboxPassword,
		otpSecretKey:    otpSecretKey,
	}

	f.features = (&fs.Features{
		ReadMimeType:            true,
		CanHaveEmptyDirectories: true,
		/* can't have multiple threads downloading
		The raw file is split into equally-sized (currently 4MB, but it might change in the future, say to 8MB, 16MB, etc.) blocks, except the last one which might be smaller than 4MB.
		Each block is encrypted separately, where the size and sha1 after the encryption is performed on the block is added to the metadata of the block, but the original block size and sha1 is not in the metadata.
		We can make assumption and implement the chunker, but for now, we would rather be safe about it, and let the block being concurrently downloaded and decrypted in the background, to speed up the download operation!
		*/
		NoMultiThreading: true,
		PutStream:        f.PutStream,
		ListR:            f.ListR,
		Shutdown:         f.Shutdown,
		UserInfo:         f.UserInfo,
		ChangeNotify:     f.ChangeNotify,
		PublicLink:       f.PublicLink,
	}).Fill(ctx, f)

	httpClient := newHTTPClientFromFs(ctx)
	f.client, err = protondriveapi.NewProtonClient(httpClient, opt.APIURL, opt.AppVersion)
	if err != nil {
		return nil, fmt.Errorf("couldn't create Proton API client: %w", err)
	}

	if err := f.bootstrapClient(ctx); err != nil {
		return nil, err
	}

	root = f.sanitizePath(root)
	f.dirCache = dircache.New(
		root,         /* root folder path */
		f.rootLinkID, /* real root ID is the root folder */
		f,
	)
	err = f.dirCache.FindRoot(ctx, false)
	if err != nil {
		// if the root directory is not found, the initialization will still work
		// but if it's other kinds of error, then we raise it
		if !errors.Is(err, fs.ErrorDirNotFound) {
			return nil, fmt.Errorf("couldn't initialize a new root remote: %w", err)
		}

		// Assume it is a file (taken and modified from box.go)
		newRoot, remote := dircache.SplitPath(root)
		tempF := *f
		tempF.dirCache = dircache.New(newRoot, f.rootLinkID, &tempF)
		tempF.root = newRoot
		// Make new Fs which is the parent
		err = tempF.dirCache.FindRoot(ctx, false)
		if err != nil {
			// No root so return old f
			// Start the event poller before returning — dirCache is set.
			f.startEventPoller(ctx)
			return f, nil
		}
		_, err := tempF.newObject(ctx, remote)
		if err != nil {
			if errors.Is(err, fs.ErrorObjectNotFound) {
				// File doesn't exist so return old f
				// Start the event poller before returning — dirCache is set.
				f.startEventPoller(ctx)
				return f, nil
			}
			return nil, err
		}
		f.features.Fill(ctx, &tempF)
		// XXX: update the old f here instead of returning tempF, since
		// `features` were already filled with functions having *f as a receiver.
		// See https://github.com/rclone/rclone/issues/2182
		f.dirCache = tempF.dirCache
		f.root = tempF.root
		// Start the event poller now that dirCache is fully initialised.
		f.startEventPoller(ctx)
		// return an error with an fs which points to the parent
		return f, fs.ErrorIsFile
	}

	// Start the event poller now that dirCache is fully initialised.
	// Doing so here (rather than before dirCache creation) eliminates the
	// window where the poller goroutine could call f.dirCache.GetInv on a
	// nil dirCache if an event fires during NewFs initialisation.
	f.startEventPoller(ctx)

	return f, nil
}

//------------------------------------------------------------------------------

// Precision of the ModTimes in this Fs
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// DirCacheFlush an optional interface to flush internal directory cache
// DirCacheFlush resets the directory cache - used in testing
// as an optional interface
func (f *Fs) DirCacheFlush() {
	f.flushCaches()
	// Re-cache the root link keyring after flush
	var filesShare *protondriveapi.FilesShareResp
	if err := f.pacer.Call(func() (bool, error) {
		var e error
		filesShare, e = f.client.GetFilesShare(f.ctx)
		return shouldRetry(f.ctx, e)
	}); err != nil {
		fs.Debugf(f, "DirCacheFlush: get files share: %v", err)
		return
	}
	if err := f.unlockShareKeyring(f.ctx, filesShare); err != nil {
		fs.Debugf(f, "DirCacheFlush: unlock share keyring: %v", err)
	}
}

// Hashes returns the supported hash types of the filesystem
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.SHA1)
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	var user *protondriveapi.User
	var err error
	if err = f.pacer.Call(func() (bool, error) {
		user, err = f.client.GetUser(ctx)
		return shouldRetry(ctx, err)
	}); err != nil {
		return nil, err
	}

	total := user.MaxSpace
	used := user.UsedSpace
	free := total - used
	if free < 0 {
		free = 0
	}

	usage := &fs.Usage{
		Total: &total,
		Used:  &used,
		Free:  &free,
	}

	return usage, nil
}

// CleanUp deletes all files currently in trash
func (f *Fs) CleanUp(ctx context.Context) error {
	return f.pacer.Call(func() (bool, error) {
		err := f.client.EmptyTrash(ctx, f.volumeID)
		return shouldRetry(ctx, err)
	})
}

// Disconnect the current user
func (f *Fs) Disconnect(ctx context.Context) error {
	// Stop the event poller
	f.stopPoller()

	err := f.pacer.Call(func() (bool, error) {
		err := f.client.Logout(ctx)
		return shouldRetry(ctx, err)
	})
	clearConfigMap(f.m)
	return err
}

// Shutdown stops background goroutines (the event poller) without logging out.
// Implements fs.Shutdowner.
func (f *Fs) Shutdown(_ context.Context) error {
	f.stopPoller()
	return nil
}

// UserInfo returns information about the connected user.
// Implements fs.UserInfoer.
func (f *Fs) UserInfo(ctx context.Context) (map[string]string, error) {
	var user *protondriveapi.User
	var err error
	if err = f.pacer.Call(func() (bool, error) {
		user, err = f.client.GetUser(ctx)
		return shouldRetry(ctx, err)
	}); err != nil {
		return nil, err
	}
	return map[string]string{
		"username":   user.Name,
		"email":      f.addrEmail,
		"used_space": fmt.Sprintf("%d", user.UsedSpace),
		"max_space":  fmt.Sprintf("%d", user.MaxSpace),
	}, nil
}
