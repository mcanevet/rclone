package protondrive

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
)

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
// Notice that this function is expensive since everything on proton is encrypted
// So having a remote with 10k files, during operations like sync, might take a while and lots of bandwidth!
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	folderLinkID, err := f.dirCache.FindDir(ctx, f.sanitizePath(dir), false)
	if err != nil {
		return nil, err
	}

	parentKR, err := f.unlockLink(ctx, folderLinkID)
	if err != nil {
		return nil, fmt.Errorf("List: unlock folder: %w", err)
	}
	addrKR := f.client.GetPrimaryKR()

	var entries fs.DirEntries
	if err = f.pacer.Call(func() (bool, error) {
		entries = nil
		walkErr := f.client.WalkFolderChildren(ctx, f.volumeID, folderLinkID, func(batch []protondriveapi.LinkWrapper) error {
			for i := range batch {
				child := &batch[i]
				if child.Link.State != protondriveapi.LinkStateActive {
					continue
				}

				decName, decErr := protondriveapi.DecryptName(child.Link.Name, parentKR, addrKR)
				if decErr != nil {
					fs.Debugf(f, "List: decrypt name for %s: %v", child.Link.LinkID, decErr)
					continue
				}

				remote := path.Join(dir, f.opt.Enc.ToStandardName(decName))

				if child.Link.Type == protondriveapi.LinkTypeFolder {
					f.dirCache.Put(remote, child.Link.LinkID)
					d := fs.NewDir(remote, time.Unix(child.Link.ModifyTime, 0)).SetID(child.Link.LinkID)
					entries = append(entries, d)
				} else {
					obj, objErr := f.newObjectWithLink(ctx, remote, child)
					if objErr != nil {
						fs.Debugf(f, "List: skipping %s: %v", child.Link.LinkID, objErr)
						continue
					}
					entries = append(entries, obj)
				}
			}
			return nil
		})
		return shouldRetry(ctx, walkErr)
	}); err != nil {
		return nil, err
	}

	return entries, nil
}

// ListR lists the directory recursively calling the callback for each entry.
// The entries can be returned in any order but they should be
// temporary objects which should not be retained.
//
// dir should be "" to list the root, and should not have
// temporary objects.
//
// This should return ErrDirNotFound if the directory isn't
// found.
//
// It should call callback for each tranche of entries
func (f *Fs) ListR(ctx context.Context, dir string, callback fs.ListRCallback) error {
	return f.listR(ctx, dir, callback)
}

// listR is the recursive helper for ListR
func (f *Fs) listR(ctx context.Context, dir string, callback fs.ListRCallback) error {
	entries, err := f.List(ctx, dir)
	if err != nil {
		return err
	}
	if err = callback(entries); err != nil {
		return err
	}
	for _, entry := range entries {
		if d, ok := entry.(fs.Directory); ok {
			if err = f.listR(ctx, d.Remote(), callback); err != nil {
				return err
			}
		}
	}
	return nil
}

// FindLeaf finds a directory of name leaf in the folder with ID pathID
//
// This should be implemented by the backend and will be called by the
// dircache package when appropriate.
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (string, bool, error) {
	/* f.opt.Enc.FromStandardName(leaf) not required since the DirCache only process sanitized path */

	link, err := f.findLinkByName(ctx, pathID, leaf, true)
	if err != nil {
		return "", false, err
	}
	if link == nil {
		return "", false, nil
	}

	return link.Link.LinkID, true, nil
}

// CreateDir makes a directory with pathID as parent and name leaf
//
// This should be implemented by the backend and will be called by the
// dircache package when appropriate.
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (string, error) {
	/* f.opt.Enc.FromStandardName(leaf) not required since the DirCache only process sanitized path */

	parentKR, err := f.unlockLink(ctx, pathID)
	if err != nil {
		return "", fmt.Errorf("CreateDir: unlock parent: %w", err)
	}
	addrKR := f.client.GetPrimaryKR()

	// Generate node keys
	nodeKeyArmored, passphraseEnc, passphraseSignature, err := protondriveapi.GenerateNodeKeys(parentKR, addrKR)
	if err != nil {
		return "", fmt.Errorf("CreateDir: generate node keys: %w", err)
	}

	// Unlock the node keyring so we can encrypt the hash key to it
	nodeKR, err := protondriveapi.UnlockNodeKey(nodeKeyArmored, passphraseEnc, passphraseSignature, parentKR, addrKR)
	if errors.Is(err, protondriveapi.ErrPassphraseSignatureMismatch) {
		fs.Debugf(f, "CreateDir: %v", err)
	} else if err != nil {
		return "", fmt.Errorf("CreateDir: unlock node key: %w", err)
	}

	// Generate a random hash key for the new node and encrypt it to the node keyring
	newHashKeyRaw, err := pgpcrypto.RandomToken(32)
	if err != nil {
		return "", fmt.Errorf("CreateDir: generate hash key: %w", err)
	}
	encHashKey, err := protondriveapi.EncryptHashKey(newHashKeyRaw, nodeKR, addrKR)
	if err != nil {
		return "", fmt.Errorf("CreateDir: encrypt hash key: %w", err)
	}

	// Fetch the parent link to get its hash key for name hash computation.
	// The name hash must use the PARENT's hash key, not the new node's.
	pl, err := f.getLink(ctx, pathID)
	if err != nil {
		return "", fmt.Errorf("CreateDir: get parent link: %w", err)
	}
	parentHashKeyRaw, err := f.getHashKeyForLink(pl, parentKR)
	if err != nil {
		return "", fmt.Errorf("CreateDir: %w", err)
	}

	// Encrypt the folder name
	encName, err := protondriveapi.EncryptName(leaf, parentKR, addrKR)
	if err != nil {
		return "", fmt.Errorf("CreateDir: encrypt name: %w", err)
	}

	// Compute name hash using the PARENT's hash key
	nameHash, err := protondriveapi.ComputeNameHash(leaf, parentHashKeyRaw)
	if err != nil {
		return "", fmt.Errorf("CreateDir: compute name hash: %w", err)
	}

	var newID string
	if err = f.pacer.Call(func() (bool, error) {
		newID, err = f.client.CreateFolder(ctx, f.volumeID, &protondriveapi.CreateFolderReq{
			CreateNodeReq: protondriveapi.CreateNodeReq{
				ParentLinkID:            pathID,
				Name:                    encName,
				Hash:                    nameHash,
				NodeKey:                 nodeKeyArmored,
				NodePassphrase:          passphraseEnc,
				NodePassphraseSignature: passphraseSignature,
				SignatureEmail:          f.addrEmail,
			},
			NodeHashKey: encHashKey,
		})
		return shouldRetry(ctx, err)
	}); err != nil {
		return "", err
	}

	// Cache the new folder's keyring
	f.linkKRCache.Add(newID, nodeKR)

	return newID, nil
}

// Mkdir makes the directory (container, bucket)
//
// Shouldn't return an error if it already exists
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.dirCache.FindDir(ctx, f.sanitizePath(dir), true)
	return err
}

// Rmdir removes the directory (container, bucket) if empty
//
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	folderLinkID, err := f.dirCache.FindDir(ctx, f.sanitizePath(dir), false)
	if errors.Is(err, fs.ErrorDirNotFound) {
		return fmt.Errorf("Rmdir %q: %w", dir, err)
	} else if err != nil {
		return err
	}

	// Check if the directory is empty before trashing
	var children []protondriveapi.LinkWrapper
	if err = f.pacer.Call(func() (bool, error) {
		children, err = f.client.ListFolderChildren(ctx, f.volumeID, folderLinkID)
		return shouldRetry(ctx, err)
	}); err != nil {
		return err
	}
	for _, child := range children {
		if child.Link.State == protondriveapi.LinkStateActive {
			return fs.ErrorDirectoryNotEmpty
		}
	}

	if err = f.pacer.Call(func() (bool, error) {
		err = f.client.TrashLinks(ctx, f.volumeID, []string{folderLinkID})
		return shouldRetry(ctx, err)
	}); err != nil {
		return err
	}

	f.dirCache.FlushDir(f.sanitizePath(dir))
	return nil
}

// Purge all files in the directory specified
//
// Implement this if you have a way of deleting all the files
// quicker than just running Remove() on the result of List()
//
// Return an error if it doesn't exist
func (f *Fs) Purge(ctx context.Context, dir string) error {
	root := path.Join(f.root, dir)
	if root == "" {
		// we can't remove the root directory, but we can list the directory and delete every folder and file in here
		return errCanNotPurgeRootDirectory
	}

	folderLinkID, err := f.dirCache.FindDir(ctx, f.sanitizePath(dir), false)
	if err != nil {
		return err
	}

	if err = f.pacer.Call(func() (bool, error) {
		err = f.client.TrashLinks(ctx, f.volumeID, []string{folderLinkID})
		return shouldRetry(ctx, err)
	}); err != nil {
		return err
	}

	f.dirCache.FlushDir(f.sanitizePath(dir))
	f.linkKRCache.Purge()
	return nil
}

// DirMove moves src, srcRemote to this remote at dstRemote
// using server-side move operations.
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantDirMove
//
// If destination exists then return fs.ErrorDirExists
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	srcFs, ok := src.(*Fs)
	if !ok {
		fs.Debugf(src, "Can't move directory - not same remote type")
		return fs.ErrorCantDirMove
	}

	srcID, _, _, dstDirectoryID, dstLeaf, err := f.dirCache.DirMove(ctx, srcFs.dirCache, srcFs.sanitizePath(srcFs.root), srcFs.sanitizePath(srcRemote), f.sanitizePath(f.root), f.sanitizePath(dstRemote))
	if err != nil {
		return err
	}

	// Get source link
	srcLink, fetchErr := f.getLink(ctx, srcID)
	if fetchErr != nil {
		return fmt.Errorf("DirMove: get src link: %w", fetchErr)
	}

	if err := f.moveLinkInternal(ctx, srcID, srcLink, dstDirectoryID, dstLeaf); err != nil {
		return err
	}

	srcFs.dirCache.FlushDir(srcFs.sanitizePath(srcRemote))

	return nil
}
