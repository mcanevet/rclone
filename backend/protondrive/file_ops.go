package protondrive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
)

// errFoundLink is used as a sentinel to stop WalkFolderChildren early once
// findLinkByName has matched a child. It is never surfaced to callers.
var errFoundLink = errors.New("found")

// unlockLinkMaxDepth is the maximum parent-chain depth allowed by unlockLink.
// A legitimate Proton Drive tree is unlikely to exceed a few hundred levels;
// this limit guards against malicious or corrupted ParentLinkID cycles.
const unlockLinkMaxDepth = 512

// unlockLink returns the unlocked KeyRing for a given linkID.
// It walks the parent chain up to the root, caching each KR along the way.
func (f *Fs) unlockLink(ctx context.Context, linkID string) (*pgpcrypto.KeyRing, error) {
	visited := make(map[string]struct{})

	var rec func(linkID string, depth int) (*pgpcrypto.KeyRing, error)
	rec = func(linkID string, depth int) (*pgpcrypto.KeyRing, error) {
		if depth > unlockLinkMaxDepth {
			return nil, fmt.Errorf("unlockLink %s: parent chain exceeds maximum depth %d", linkID, unlockLinkMaxDepth)
		}

		// Check cache first
		if kr, ok := f.linkKRCache.Get(linkID); ok {
			return kr, nil
		}

		// Empty linkID means the caller is asking for the parent of the root link,
		// which is the share keyring. Return it directly without a network call.
		if linkID == "" {
			if f.shareKR == nil {
				return nil, fmt.Errorf("unlockLink: share keyring not initialised")
			}
			return f.shareKR, nil
		}

		// Cycle detection: fail if this linkID is already on the call stack.
		if _, seen := visited[linkID]; seen {
			return nil, fmt.Errorf("unlockLink %s: cycle detected in parent chain", linkID)
		}
		visited[linkID] = struct{}{}

		// Fetch the link
		var links []protondriveapi.LinkWrapper
		if err := f.pacer.Call(func() (bool, error) {
			var callErr error
			links, callErr = f.client.BatchGetLinks(ctx, f.volumeID, []string{linkID})
			return shouldRetry(ctx, callErr)
		}); err != nil {
			return nil, fmt.Errorf("unlockLink %s: %w", linkID, err)
		}
		if len(links) == 0 {
			return nil, fmt.Errorf("unlockLink %s: link not found", linkID)
		}
		link := links[0]

		// Get the parent keyring (recursive)
		parentKR, err := rec(link.Link.ParentLinkID, depth+1)
		if err != nil {
			return nil, fmt.Errorf("unlockLink %s: parent: %w", linkID, err)
		}

		addrKR := f.client.GetPrimaryKR()
		nodeKR, err := protondriveapi.UnlockNodeKey(link.Link.NodeKey, link.Link.NodePassphrase, link.Link.NodePassphraseSignature, parentKR, addrKR)
		if errors.Is(err, protondriveapi.ErrPassphraseSignatureMismatch) {
			fs.Debugf(f, "unlockLink %s: %v", linkID, err)
		} else if err != nil {
			return nil, fmt.Errorf("unlockLink %s: unlock node key: %w", linkID, err)
		}

		f.linkKRCache.Add(linkID, nodeKR)

		return nodeKR, nil
	}

	return rec(linkID, 0)
}

// getLink fetches a single link by ID from the volume.
func (f *Fs) getLink(ctx context.Context, linkID string) (*protondriveapi.LinkWrapper, error) {
	var links []protondriveapi.LinkWrapper
	if err := f.pacer.Call(func() (bool, error) {
		var callErr error
		links, callErr = f.client.BatchGetLinks(ctx, f.volumeID, []string{linkID})
		return shouldRetry(ctx, callErr)
	}); err != nil {
		return nil, fmt.Errorf("getLink %s: %w", linkID, err)
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("getLink %s: link not found", linkID)
	}
	return &links[0], nil
}

// getHashKeyForLink returns the decrypted NodeHashKey for the given folder
// link, trying nodeKR, addrKR, and userKR in order.
// Returns an error if the link has no NodeHashKey or decryption fails.
func (f *Fs) getHashKeyForLink(link *protondriveapi.LinkWrapper, nodeKR *pgpcrypto.KeyRing) ([]byte, error) {
	if link.Folder == nil || link.Folder.NodeHashKey == "" {
		return nil, fmt.Errorf("getHashKeyForLink %s: folder has no NodeHashKey", link.Link.LinkID)
	}
	addrKR := f.client.GetPrimaryKR()
	// Try nodeKR+addrKR (the common case), then bare addrKR, then userKR.
	for _, pair := range [][2]*pgpcrypto.KeyRing{
		{nodeKR, addrKR},
		{addrKR, nil},
		{f.client.GetUserKR(), nil},
	} {
		if pair[0] == nil {
			continue
		}
		raw, err := protondriveapi.DecryptHashKey(link.Folder.NodeHashKey, pair[0], pair[1])
		if err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("getHashKeyForLink: could not decrypt NodeHashKey (tried nodeKR, addrKR, userKR)")
}

// findLinkByName searches a folder for a child with the given decrypted name.
// If wantFolder is true, only folders are returned; if false, only files.
// Returns (nil, nil) if not found.
func (f *Fs) findLinkByName(ctx context.Context, folderLinkID, name string, wantFolder bool) (*protondriveapi.LinkWrapper, error) {
	// Unlock the parent folder KR so we can decrypt child names
	parentKR, err := f.unlockLink(ctx, folderLinkID)
	if err != nil {
		return nil, fmt.Errorf("findLinkByName: unlock parent: %w", err)
	}
	addrKR := f.client.GetPrimaryKR()

	// Walk children in streaming batches; stop as soon as we find a match.
	var found *protondriveapi.LinkWrapper
	if err := f.pacer.Call(func() (bool, error) {
		found = nil
		walkErr := f.client.WalkFolderChildren(ctx, f.volumeID, folderLinkID, func(batch []protondriveapi.LinkWrapper) error {
			for i := range batch {
				child := &batch[i]
				if child.Link.State != protondriveapi.LinkStateActive {
					continue
				}
				if wantFolder && child.Link.Type != protondriveapi.LinkTypeFolder {
					continue
				}
				if !wantFolder && child.Link.Type != protondriveapi.LinkTypeFile {
					continue
				}
				decName, decErr := protondriveapi.DecryptName(child.Link.Name, parentKR, addrKR)
				if decErr != nil {
					fs.Debugf(f, "findLinkByName: decrypt name for %s: %v", child.Link.LinkID, decErr)
					continue
				}
				if decName == name {
					cp := *child // copy so we can store a pointer safely
					found = &cp
					return errFoundLink // stop the walk early
				}
			}
			return nil
		})
		if errors.Is(walkErr, errFoundLink) {
			return false, nil // not a retryable error; found is set
		}
		return shouldRetry(ctx, walkErr)
	}); err != nil {
		return nil, fmt.Errorf("findLinkByName: list children: %w", err)
	}
	return found, nil
}

// readMetaDataForLink reads the XAttr metadata for a file link.
// Returns nil attrs (no error) if the link has no active revision XAttr.
func (f *Fs) readMetaDataForLink(ctx context.Context, link *protondriveapi.LinkWrapper) (*protondriveapi.RevisionXAttrCommon, error) {
	// Get the file's node keyring
	nodeKR, err := f.unlockLink(ctx, link.Link.LinkID)
	if err != nil {
		return nil, fmt.Errorf("readMetaDataForLink: unlock link: %w", err)
	}

	// Find the active revision's XAttr. The batch link response may return a
	// non-nil ActiveRevision but with an empty XAttr field (the server omits it
	// for large revisions). In that case we fetch the full revision directly.
	var xattrStr string
	if link.File != nil && link.File.ActiveRevision != nil {
		xattrStr = link.File.ActiveRevision.XAttr
		if xattrStr == "" {
			// XAttr was absent in the batch response; fetch the full revision.
			var rev *protondriveapi.Revision
			if err := f.pacer.Call(func() (bool, error) {
				var e error
				rev, e = f.client.GetRevision(ctx, f.volumeID, link.Link.LinkID, link.File.ActiveRevision.RevisionID)
				return shouldRetry(ctx, e)
			}); err != nil {
				return nil, fmt.Errorf("readMetaDataForLink: get revision: %w", err)
			}
			xattrStr = rev.XAttr
		}
	}

	if xattrStr == "" {
		return nil, nil
	}

	attrs, err := protondriveapi.DecryptXAttr(xattrStr, nodeKR, f.client.GetPrimaryKR())
	if err != nil {
		return nil, fmt.Errorf("readMetaDataForLink: decrypt xattr: %w", err)
	}
	return attrs, nil
}

// newObjectWithLink returns an Object from a path and link.
//
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObjectWithLink(ctx context.Context, remote string, link *protondriveapi.LinkWrapper) (fs.Object, error) {
	var size int64
	var mimeType string
	if link.File != nil {
		size = link.File.TotalEncryptedSize
		mimeType = link.File.MediaType
	}
	o := &Object{
		fs:          f,
		remote:      remote,
		id:          link.Link.LinkID,
		parentID:    link.Link.ParentLinkID,
		size:        size,
		modTime:     time.Unix(link.Link.ModifyTime, 0),
		createdTime: time.Unix(link.Link.CreateTime, 0),
		mimetype:    mimeType,
	}

	attrs, err := f.readMetaDataForLink(ctx, link)
	if err != nil {
		return nil, err
	}
	if attrs != nil {
		if t, parseErr := time.Parse(time.RFC3339, attrs.ModificationTime); parseErr == nil {
			o.modTime = t
		}
		o.originalSize = &attrs.Size
		o.blockSizes = attrs.BlockSizes
		if sha1, ok := attrs.Digests["SHA1"]; ok {
			o.digests = &sha1
		}
	}

	return o, nil
}

// newObject returns an Object from a path only.
//
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObject(ctx context.Context, remote string) (fs.Object, error) {
	// attempt to locate the file
	leaf, folderLinkID, err := f.dirCache.FindPath(ctx, f.sanitizePath(remote), false)
	if err != nil {
		if errors.Is(err, fs.ErrorDirNotFound) {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, err
	}

	link, err := f.findLinkByName(ctx, folderLinkID, leaf, false)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, fs.ErrorObjectNotFound
	}
	return f.newObjectWithLink(ctx, remote, link)
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error ErrorObjectNotFound.
//
// If remote points to a directory then it should return
// ErrorIsDir if possible without doing any extra work,
// otherwise ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	obj, err := f.newObject(ctx, remote)
	if errors.Is(err, fs.ErrorObjectNotFound) {
		// Check if it's a directory instead
		leaf, folderLinkID, findErr := f.dirCache.FindPath(ctx, f.sanitizePath(remote), false)
		if findErr == nil {
			dirLink, findErr := f.findLinkByName(ctx, folderLinkID, leaf, true)
			if findErr == nil && dirLink != nil {
				return nil, fs.ErrorIsDir
			}
		}
		return nil, fs.ErrorObjectNotFound
	}
	return obj, err
}

// createObject creates a half-finished Object which must have Update called on it.
//
// Returns the object, leaf, directoryID and error.
//
// Used to create new objects.
func (f *Fs) createObject(ctx context.Context, remote string, modTime time.Time, size int64) (*Object, error) {
	// Create the directory for the object if it doesn't exist
	_, _, err := f.dirCache.FindPath(ctx, f.sanitizePath(remote), true)
	if err != nil {
		return nil, err
	}

	// Temporary Object under construction
	obj := &Object{
		fs:           f,
		remote:       remote,
		size:         size,
		originalSize: nil,
		id:           "",
		modTime:      modTime,
		mimetype:     "",
	}
	return obj, nil
}

// Put in to the remote path with the modTime given of the given size
//
// When called from outside an Fs by rclone, src.Size() will always be >= 0.
// But for unknown-sized objects (indicated by src.Size() == -1), Put should either
// return an error or upload it properly (rather than e.g. calling panic).
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	size := src.Size()
	if size < 0 {
		return nil, errCanNotUploadFileWithUnknownSize
	}
	return f.putOrStream(ctx, in, src, size, options...)
}

// PutStream uploads to the remote path with the modtime given of indeterminate size
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.putOrStream(ctx, in, src, -1, options...)
}

// putOrStream is the common implementation for Put and PutStream.
// size is passed to createObject; -1 means unknown (streaming upload).
func (f *Fs) putOrStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, size int64, options ...fs.OpenOption) (fs.Object, error) {
	existingObj, err := f.NewObject(ctx, src.Remote())
	switch err {
	case nil:
		// object is found, we add a revision to it
		return existingObj, existingObj.Update(ctx, in, src, options...)
	case fs.ErrorObjectNotFound:
		// object not found, so we need to create it
		obj, err := f.createObject(ctx, src.Remote(), src.ModTime(ctx), size)
		if err != nil {
			return nil, err
		}
		return obj, obj.Update(ctx, in, src, options...)
	default:
		return nil, err
	}
}

// Move src to this remote using server-side move operations.
//
// This is stored with the remote path given.
//
// It returns the destination Object and a possible error.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same remote type")
		return nil, fs.ErrorCantMove
	}

	// check if the remote (dst) exists — if so, delete it first
	// (the fs.Mover contract requires server-side replacement)
	existingObj, err := f.NewObject(ctx, remote)
	if err != nil {
		if !errors.Is(err, fs.ErrorObjectNotFound) {
			return nil, err
		}
		// object is indeed not found — proceed
	} else {
		// object at the dst exists — delete it before moving
		existingTyped, ok := existingObj.(*Object)
		if !ok {
			return nil, fmt.Errorf("Move: existing dst is unexpected type %T", existingObj)
		}
		if err := existingTyped.Remove(ctx); err != nil {
			return nil, fmt.Errorf("Move: remove existing dst: %w", err)
		}
	}

	// attempt the move
	dstLeaf, dstDirectoryID, err := f.dirCache.FindPath(ctx, f.sanitizePath(remote), true)
	if err != nil {
		return nil, err
	}

	// Get the source link to re-encrypt passphrase for the new parent
	srcLink, err := f.getLink(ctx, srcObj.id)
	if err != nil {
		return nil, fmt.Errorf("Move: get src link: %w", err)
	}

	if err := f.moveLinkInternal(ctx, srcObj.id, srcLink, dstDirectoryID, dstLeaf); err != nil {
		return nil, err
	}

	// Flush the parent directory of the source path from the dircache
	// (FlushDir on a file path is a no-op).
	srcParentDir := path.Dir(f.sanitizePath(src.Remote()))
	if srcParentDir == "." {
		srcParentDir = ""
	}
	f.dirCache.FlushDir(srcParentDir)

	return f.NewObject(ctx, remote)
}

// moveLinkInternal performs the common crypto work (re-encrypt passphrase and
// name, compute new name hash) and issues the MoveLink API call.
// srcLinkID is the ID of the link being moved; srcLink is its fetched metadata.
// dstDirectoryID is the destination parent folder link ID; dstLeaf is the new
// leaf name in the destination.
func (f *Fs) moveLinkInternal(ctx context.Context, srcLinkID string, srcLink *protondriveapi.LinkWrapper, dstDirectoryID, dstLeaf string) error {
	dstParentKR, err := f.unlockLink(ctx, dstDirectoryID)
	if err != nil {
		return fmt.Errorf("moveLinkInternal: unlock dst parent: %w", err)
	}
	addrKR := f.client.GetPrimaryKR()

	dstParentLink, err := f.getLink(ctx, dstDirectoryID)
	if err != nil {
		return fmt.Errorf("moveLinkInternal: get dst parent link: %w", err)
	}
	dstHashKeyRaw, err := f.getHashKeyForLink(dstParentLink, dstParentKR)
	if err != nil {
		return fmt.Errorf("moveLinkInternal: %w", err)
	}

	srcParentKR, err := f.unlockLink(ctx, srcLink.Link.ParentLinkID)
	if err != nil {
		return fmt.Errorf("moveLinkInternal: unlock src parent: %w", err)
	}

	newPassphraseEnc, err := protondriveapi.ReEncryptPassphrase(srcLink.Link.NodePassphrase, srcParentKR, dstParentKR, addrKR, f.client.GetUserKR())
	if err != nil {
		return fmt.Errorf("moveLinkInternal: %w", err)
	}

	encNewName, err := protondriveapi.ReEncryptName(srcLink.Link.Name, dstLeaf, srcParentKR, dstParentKR, addrKR, f.client.GetUserKR())
	if err != nil {
		return fmt.Errorf("moveLinkInternal: %w", err)
	}
	newNameHash, err := protondriveapi.ComputeNameHash(dstLeaf, dstHashKeyRaw)
	if err != nil {
		return fmt.Errorf("moveLinkInternal: compute new name hash: %w", err)
	}

	req := &protondriveapi.MoveLinkReq{
		Name:               encNewName,
		Hash:               newNameHash,
		OriginalHash:       srcLink.Link.NameHash,
		NodePassphrase:     newPassphraseEnc,
		NameSignatureEmail: f.addrEmail,
		ContentHash:        nil,
	}

	if srcLink.Link.ParentLinkID == dstDirectoryID {
		// Same folder: use rename endpoint (no ParentLinkID in request).
		return f.pacer.Call(func() (bool, error) {
			err := f.client.RenameLink(ctx, f.volumeID, srcLinkID, req)
			return shouldRetry(ctx, err)
		})
	}

	req.ParentLinkID = dstDirectoryID
	return f.pacer.Call(func() (bool, error) {
		err := f.client.MoveLink(ctx, f.volumeID, srcLinkID, req)
		return shouldRetry(ctx, err)
	})
}
