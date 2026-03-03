package protondrive

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/readers"
)

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the hashes of an object
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t != hash.SHA1 {
		return "", hash.ErrUnsupported
	}

	if o.digests != nil {
		return *o.digests, nil
	}

	// sha1 not cached: try fetching via the link
	leaf, folderLinkID, err := o.fs.dirCache.FindPath(ctx, o.fs.sanitizePath(o.remote), false)
	if err != nil {
		return "", fmt.Errorf("Hash: find path: %w", err)
	}
	link, err := o.fs.findLinkByName(ctx, folderLinkID, leaf, false)
	if err != nil {
		return "", fmt.Errorf("Hash: find link: %w", err)
	}
	if link == nil {
		return "", fs.ErrorObjectNotFound
	}
	attrs, err := o.fs.readMetaDataForLink(ctx, link)
	if err != nil {
		return "", fmt.Errorf("Hash: read metadata: %w", err)
	}
	if attrs == nil {
		return "", nil
	}
	if sha1, ok := attrs.Digests["SHA1"]; ok {
		return sha1, nil
	}
	return "", nil
}

// Size returns the size of an object in bytes.
//
// When ReportOriginalSize is enabled and the original (pre-encryption) size has
// been decoded from the XAttr, that value is returned. This is necessary for
// correct seek/range support in Open(), which uses the size to clamp offsets.
//
// Degraded mode: if ReportOriginalSize is set but originalSize is nil (XAttr
// not yet decoded, e.g. during a shallow listing), Size() falls back to
// o.size — the encrypted block size reported by the API — and logs a debug
// message. Callers that rely on the exact byte count (e.g. checksum
// verification) may see an inflated value in this case.
func (o *Object) Size() int64 {
	if o.fs.opt.ReportOriginalSize {
		// if ReportOriginalSize is set, we will generate an error when the original size failed to be parsed
		// this is crucial as features like Open() will need to use the proper size to operate the seek/range operator
		if o.originalSize != nil {
			return *o.originalSize
		}

		fs.Debugf(o, "Original file size missing")
	}
	return o.size
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable returns a boolean showing whether this object storable
func (o *Object) Storable() bool {
	return true
}

// Open opens the file for read.  Call Close() on the returned io.ReadCloser
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	if o.originalSize != nil {
		fs.FixRangeOption(options, *o.originalSize)
	}
	var offset, limit int64 = 0, -1
	for _, option := range options {
		switch x := option.(type) {
		case *fs.SeekOption:
			offset = x.Offset
		case *fs.RangeOption:
			offset, limit = x.Decode(o.Size())
		default:
			if option.Mandatory() {
				fs.Logf(o, "Unsupported mandatory option: %v", option)
			}
		}
	}

	// Get the link to find the active revision
	leaf, folderLinkID, err := o.fs.dirCache.FindPath(ctx, o.fs.sanitizePath(o.remote), false)
	if err != nil {
		return nil, fmt.Errorf("Open: find path: %w", err)
	}
	link, err := o.fs.findLinkByName(ctx, folderLinkID, leaf, false)
	if err != nil {
		return nil, fmt.Errorf("Open: find link: %w", err)
	}
	if link == nil {
		return nil, fs.ErrorObjectNotFound
	}

	if link.File == nil || link.File.ActiveRevision == nil {
		return nil, fmt.Errorf("Open: no active revision for %s", o.remote)
	}

	// Unlock the node keyring
	nodeKR, err := o.fs.unlockLink(ctx, link.Link.LinkID)
	if err != nil {
		return nil, fmt.Errorf("Open: unlock link: %w", err)
	}

	// Decrypt the content key packet
	sessionKey, err := protondriveapi.DecryptContentKeyPacket(link.File.ContentKeyPacket, nodeKR)
	if err != nil {
		return nil, fmt.Errorf("Open: decrypt content key: %w", err)
	}

	// Get the revision blocks
	var rev *protondriveapi.Revision
	if err := o.fs.pacer.Call(func() (bool, error) {
		var e error
		rev, e = o.fs.client.GetRevision(ctx, o.fs.volumeID, link.Link.LinkID, link.File.ActiveRevision.RevisionID)
		return shouldRetry(ctx, e)
	}); err != nil {
		return nil, fmt.Errorf("Open: get revision: %w", err)
	}

	// Update metadata from XAttr if available
	if rev.XAttr != "" {
		attrs, err := protondriveapi.DecryptXAttr(rev.XAttr, nodeKR, o.fs.client.GetPrimaryKR())
		if err == nil && attrs != nil {
			if t, parseErr := time.Parse(time.RFC3339, attrs.ModificationTime); parseErr == nil {
				o.modTime = t
			}
			o.originalSize = &attrs.Size
			o.blockSizes = attrs.BlockSizes
			if sha1, ok := attrs.Digests["SHA1"]; ok {
				o.digests = &sha1
			}
		}
	}

	// Stream download: decrypt blocks in a goroutine and pipe to caller.
	// This avoids loading the entire file into memory at once.
	pr, pw := io.Pipe()
	go func() {
		for _, block := range rev.Blocks {
			var encData []byte
			if err := o.fs.pacer.Call(func() (bool, error) {
				var e error
				encData, e = o.fs.client.DownloadBlock(ctx, block.BareURL, block.Token)
				return shouldRetry(ctx, e)
			}); err != nil {
				_ = pw.CloseWithError(fmt.Errorf("Open: download block %d: %w", block.Index, err))
				return
			}
			plain, err := protondriveapi.DecryptBlock(encData, sessionKey, o.fs.client.GetPrimaryKR(), nodeKR, block.EncSignature)
			if err != nil {
				_ = pw.CloseWithError(fmt.Errorf("Open: decrypt block %d: %w", block.Index, err))
				return
			}
			if _, err := pw.Write(plain); err != nil {
				// Pipe was closed by reader (e.g. limit reached); stop silently.
				return
			}
		}
		_ = pw.Close()
	}()

	// Apply offset by discarding bytes from the front.
	var retReader io.ReadCloser = pr
	if offset > 0 {
		if _, err := io.CopyN(io.Discard, pr, offset); err != nil && err != io.EOF {
			_ = pr.CloseWithError(err)
			return nil, fmt.Errorf("Open: seek to offset: %w", err)
		}
	}
	return readers.NewLimitedReadCloser(retReader, limit), nil
}

// Update in to the object with the modTime given of the given size
//
// When called from outside an Fs by rclone, src.Size() will always be >= 0.
// When called via PutStream, src.Size() may be -1 (unknown); in that case the
// actual size is determined by the bytes read from in.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	remote := o.Remote()
	leaf, folderLinkID, err := o.fs.dirCache.FindPath(ctx, o.fs.sanitizePath(remote), true)
	if err != nil {
		return err
	}

	modTime := src.ModTime(ctx)

	// Determine if we're updating an existing file
	existingLinkID := o.id // empty string if new object

	// Note: uploadFile is NOT wrapped in pacer.Call because the io.Reader (in)
	// is not seekable — a retry after partial consumption would corrupt the
	// upload. Individual API calls inside the upload path already have their
	// own pacer wrappers.
	linkID, attrs, err := o.fs.uploadFile(ctx, folderLinkID, leaf, modTime, in, existingLinkID)
	if err != nil {
		return err
	}

	o.id = linkID
	o.modTime = modTime
	if attrs != nil {
		o.originalSize = &attrs.Size
		o.blockSizes = attrs.BlockSizes
		if sha1, ok := attrs.Digests["SHA1"]; ok {
			o.digests = &sha1
		}
	}

	return nil
}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	return o.fs.pacer.Call(func() (bool, error) {
		err := o.fs.client.TrashLinks(ctx, o.fs.volumeID, []string{o.id})
		return shouldRetry(ctx, err)
	})
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	return o.id
}

// ParentID returns the ID of the parent directory, or "" if not known.
// Implements fs.ParentIDer.
func (o *Object) ParentID() string {
	return o.parentID
}

// MimeType of an Object if known, "" otherwise
func (o *Object) MimeType(ctx context.Context) string {
	return o.mimetype
}

// Check the interfaces are satisfied
var (
	_ fs.Mover           = (*Fs)(nil)
	_ fs.DirMover        = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.Abouter         = (*Fs)(nil)
	_ fs.Purger          = (*Fs)(nil)
	_ fs.CleanUpper      = (*Fs)(nil)
	_ fs.Disconnecter    = (*Fs)(nil)
	_ fs.Shutdowner      = (*Fs)(nil)
	_ fs.UserInfoer      = (*Fs)(nil)
	_ fs.ChangeNotifier  = (*Fs)(nil)
	_ fs.PublicLinker    = (*Fs)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.MimeTyper       = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
	_ fs.ParentIDer      = (*Object)(nil)
)
