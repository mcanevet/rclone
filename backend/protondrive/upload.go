package protondrive

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"time"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"

	"github.com/rclone/rclone/backend/protondrive/protonapi"
	"github.com/rclone/rclone/backend/protondrive/protondriveapi"
	"github.com/rclone/rclone/fs"
)

// blockSize is the maximum plaintext size of each upload block (4 MiB).
const blockSize = 4 * 1024 * 1024

// prepareNewFileLink handles the new-file upload path. It generates node keys
// and a content key, creates the file link (handling draft-conflict and
// stale-link cases), caches the resulting node keyring, and returns the
// (linkID, revisionID, sessionKey, nodeKR) needed by uploadBlocks.
func (f *Fs) prepareNewFileLink(ctx context.Context, folderLinkID, leaf, mimeType string, parentKR, addrKR *pgpcrypto.KeyRing) (string, string, *pgpcrypto.SessionKey, *pgpcrypto.KeyRing, error) {
	// Generate node key pair and encrypt passphrase to parent KR.
	nodeKeyArmored, passphraseEnc, passphraseSignature, err := protondriveapi.GenerateNodeKeys(parentKR, addrKR)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: generate node keys: %w", err)
	}
	nodeKR, err := protondriveapi.UnlockNodeKey(nodeKeyArmored, passphraseEnc, passphraseSignature, parentKR, addrKR)
	if errors.Is(err, protondriveapi.ErrPassphraseSignatureMismatch) {
		fs.Debugf(f, "prepareNewFileLink: %v", err)
	} else if err != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: unlock node key: %w", err)
	}

	sessionKey, encKeyPacketB64, contentKeyPacketSig, err := protondriveapi.GenerateContentKeyPacket(nodeKR, addrKR)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: generate content key: %w", err)
	}

	// Get parent hash key for name hash computation.
	parentLink, err := f.getLink(ctx, folderLinkID)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: get parent link: %w", err)
	}
	hashKeyRaw, err := f.getHashKeyForLink(parentLink, parentKR)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: %w", err)
	}

	encName, err := protondriveapi.EncryptName(leaf, parentKR, addrKR)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: encrypt name: %w", err)
	}
	nameHash, err := protondriveapi.ComputeNameHash(leaf, hashKeyRaw)
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: compute name hash: %w", err)
	}

	createReq := &protondriveapi.CreateFileReq{
		CreateNodeReq: protondriveapi.CreateNodeReq{
			ParentLinkID:            folderLinkID,
			Name:                    encName,
			Hash:                    nameHash,
			NodeKey:                 nodeKeyArmored,
			NodePassphrase:          passphraseEnc,
			NodePassphraseSignature: passphraseSignature,
		},
		MIMEType:                  mimeType,
		ContentKeyPacket:          encKeyPacketB64,
		ContentKeyPacketSignature: contentKeyPacketSig,
		SignatureAddress:          f.addrEmail,
	}
	var linkID, revisionID string
	if err := f.pacer.Call(func() (bool, error) {
		var e error
		linkID, revisionID, e = f.client.CreateFile(ctx, f.volumeID, createReq)
		return shouldRetry(ctx, e)
	}); err != nil {
		var conflictErr *protondriveapi.CreateFileConflictError
		if !errors.As(err, &conflictErr) {
			return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: create file: %w", err)
		}
		return f.handleConflictLink(ctx, conflictErr, createReq, sessionKey, nodeKR, addrKR)
	}

	// Cache the new node keyring.
	f.linkKRCache.Add(linkID, nodeKR)
	return linkID, revisionID, sessionKey, nodeKR, nil
}

// handleConflictLink is called by prepareNewFileLink when CreateFile returns a
// Code 2500 conflict error. It handles three sub-cases:
//
//  1. ReplaceExistingDraft is false → return an error directing the user to set
//     the option.
//  2. The conflict link has a stale draft revision → delete it and create a new
//     revision on the conflict link.
//  3. The conflict link is itself stale (Code 2501 on CreateRevision) → delete
//     the conflict link and retry the original CreateFile.
func (f *Fs) handleConflictLink(ctx context.Context, conflictErr *protondriveapi.CreateFileConflictError, createReq *protondriveapi.CreateFileReq, sessionKey *pgpcrypto.SessionKey, nodeKR, addrKR *pgpcrypto.KeyRing) (string, string, *pgpcrypto.SessionKey, *pgpcrypto.KeyRing, error) {
	if !f.opt.ReplaceExistingDraft {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: file already exists (set replace_existing_draft=true to overwrite drafts): %w", conflictErr)
	}
	conflictLinkID := conflictErr.Details.ConflictLinkID
	if conflictLinkID == "" {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: conflict but no ConflictLinkID in response: %w", conflictErr)
	}

	if conflictErr.Details.ConflictDraftRevisionID != nil && *conflictErr.Details.ConflictDraftRevisionID != "" {
		// A stale draft revision exists — delete it, then create a new revision on the conflict link.
		draftRevID := *conflictErr.Details.ConflictDraftRevisionID
		if delErr := f.pacer.Call(func() (bool, error) {
			delErr := f.client.DeleteRevision(ctx, f.volumeID, conflictLinkID, draftRevID)
			return shouldRetry(ctx, delErr)
		}); delErr != nil {
			fs.Debugf(f, "prepareNewFileLink: delete draft revision %s: %v", draftRevID, delErr)
			// Non-fatal: try creating the revision anyway.
		}
	}

	// Treat as an existing-file update: unlock the conflict node KR,
	// reuse its content key, and create a new revision.
	conflictNodeKR, unlockErr := f.unlockLink(ctx, conflictLinkID)
	if unlockErr != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: unlock conflict link: %w", unlockErr)
	}

	conflictLink, fetchErr := f.getLink(ctx, conflictLinkID)
	if fetchErr != nil {
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: get conflict link: %w", fetchErr)
	}

	var (
		conflictSessionKey *pgpcrypto.SessionKey
		err                error
	)
	if conflictLink.File != nil && conflictLink.File.ContentKeyPacket != "" {
		conflictSessionKey, err = protondriveapi.DecryptContentKeyPacket(conflictLink.File.ContentKeyPacket, conflictNodeKR)
		if err != nil {
			// The existing ContentKeyPacket is undecryptable — the conflict
			// link is already broken. Delete it and retry as a completely new
			// file so the ContentKeyPacket is set correctly at creation time.
			fs.Debugf(f, "prepareNewFileLink: conflict link %s has undecryptable ContentKeyPacket, deleting and retrying: %v", conflictLinkID, err)
			if delErr := f.pacer.Call(func() (bool, error) {
				delErr := f.client.TrashLinks(ctx, f.volumeID, []string{conflictLinkID})
				return shouldRetry(ctx, delErr)
			}); delErr != nil {
				return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: delete broken conflict link: %w", delErr)
			}
			f.linkKRCache.Remove(conflictLinkID)
			var (
				linkID     string
				revisionID string
			)
			if err := f.pacer.Call(func() (bool, error) {
				var err error
				linkID, revisionID, err = f.client.CreateFile(ctx, f.volumeID, createReq)
				return shouldRetry(ctx, err)
			}); err != nil {
				return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: create file after broken conflict: %w", err)
			}
			f.linkKRCache.Add(linkID, nodeKR)
			return linkID, revisionID, sessionKey, nodeKR, nil
		}
	} else {
		// No ContentKeyPacket at all — broken conflict link; delete and retry.
		fs.Debugf(f, "prepareNewFileLink: conflict link %s has no ContentKeyPacket, deleting and retrying", conflictLinkID)
		if delErr := f.pacer.Call(func() (bool, error) {
			delErr := f.client.TrashLinks(ctx, f.volumeID, []string{conflictLinkID})
			return shouldRetry(ctx, delErr)
		}); delErr != nil {
			return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: delete broken conflict link: %w", delErr)
		}
		f.linkKRCache.Remove(conflictLinkID)
		var (
			linkID     string
			revisionID string
		)
		if err := f.pacer.Call(func() (bool, error) {
			var err error
			linkID, revisionID, err = f.client.CreateFile(ctx, f.volumeID, createReq)
			return shouldRetry(ctx, err)
		}); err != nil {
			return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: create file after broken conflict: %w", err)
		}
		f.linkKRCache.Add(linkID, nodeKR)
		return linkID, revisionID, sessionKey, nodeKR, nil
	}

	var conflictRevisionID string
	if revErr := f.pacer.Call(func() (bool, error) {
		var err error
		conflictRevisionID, err = f.client.CreateRevision(ctx, f.volumeID, conflictLinkID)
		return shouldRetry(ctx, err)
	}); revErr != nil {
		// Code 2501: the conflict link is stale and can no longer accept new revisions.
		// Trash it and retry the upload as a completely fresh file.
		if apiErr, ok := protonapi.UnwrapAPIError(revErr); ok && apiErr.Code == protondriveapi.CodeStaleRevision {
			fs.Debugf(f, "prepareNewFileLink: conflict link %s is stale (%d), deleting and retrying", conflictLinkID, protondriveapi.CodeStaleRevision)
			if delErr := f.pacer.Call(func() (bool, error) {
				delErr := f.client.DeleteDraftLinks(ctx, f.volumeID, []string{conflictLinkID})
				return shouldRetry(ctx, delErr)
			}); delErr != nil {
				fs.Debugf(f, "prepareNewFileLink: delete stale conflict link: %v", delErr)
			}
			f.linkKRCache.Remove(conflictLinkID)
			var (
				linkID     string
				revisionID string
			)
			if err := f.pacer.Call(func() (bool, error) {
				var err error
				linkID, revisionID, err = f.client.CreateFile(ctx, f.volumeID, createReq)
				return shouldRetry(ctx, err)
			}); err != nil {
				return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: create file after stale conflict: %w", err)
			}
			// Cache the new node keyring and return the fresh link.
			f.linkKRCache.Add(linkID, nodeKR)
			return linkID, revisionID, sessionKey, nodeKR, nil
		}
		return "", "", nil, nil, fmt.Errorf("prepareNewFileLink: create revision for conflict link: %w", revErr)
	}

	// Cache keyring for the conflict link so uploadBlocks can use it.
	f.linkKRCache.Add(conflictLinkID, conflictNodeKR)
	return conflictLinkID, conflictRevisionID, conflictSessionKey, conflictNodeKR, nil
}

// prepareExistingFileRevision handles the existing-file upload path. It unlocks
// the node, resolves the session key, and creates a new revision (deleting any
// draft revisions first when ReplaceExistingDraft is set). It returns
// (revisionID, sessionKey, nodeKR) needed by uploadBlocks.
func (f *Fs) prepareExistingFileRevision(ctx context.Context, linkID string, addrKR *pgpcrypto.KeyRing) (string, *pgpcrypto.SessionKey, *pgpcrypto.KeyRing, error) {
	nodeKR, err := f.unlockLink(ctx, linkID)
	if err != nil {
		return "", nil, nil, fmt.Errorf("prepareExistingFileRevision: unlock link: %w", err)
	}

	existingLink, err := f.getLink(ctx, linkID)
	if err != nil {
		return "", nil, nil, fmt.Errorf("prepareExistingFileRevision: get link: %w", err)
	}

	var sessionKey *pgpcrypto.SessionKey
	if existingLink.File != nil && existingLink.File.ContentKeyPacket != "" {
		sessionKey, err = protondriveapi.DecryptContentKeyPacket(existingLink.File.ContentKeyPacket, nodeKR)
		if err != nil {
			return "", nil, nil, fmt.Errorf("prepareExistingFileRevision: decrypt content key: %w", err)
		}
	} else {
		// Generate a new session key if we can't find the existing one.
		sessionKey, _, _, err = protondriveapi.GenerateContentKeyPacket(nodeKR, addrKR)
		if err != nil {
			return "", nil, nil, fmt.Errorf("prepareExistingFileRevision: generate content key: %w", err)
		}
	}

	// Create a new revision; if there is already a draft revision the API
	// returns an error (Code 2501). When ReplaceExistingDraft is set we
	// fetch all revisions, delete any drafts we find, and retry once.
	var revisionID string
	if err := f.pacer.Call(func() (bool, error) {
		var e error
		revisionID, e = f.client.CreateRevision(ctx, f.volumeID, linkID)
		return shouldRetry(ctx, e)
	}); err != nil {
		if !f.opt.ReplaceExistingDraft {
			return "", nil, nil, fmt.Errorf("prepareExistingFileRevision: a draft exists - usually this means a file is being uploaded by another client, or there was a failed upload attempt (set replace_existing_draft=true to replace it): %w", err)
		}
		// Try to identify and delete existing draft revisions, then retry once.
		var revisions []protondriveapi.Revision
		if listErr := f.pacer.Call(func() (bool, error) {
			var e error
			revisions, e = f.client.ListRevisions(ctx, f.volumeID, linkID)
			return shouldRetry(ctx, e)
		}); listErr == nil {
			for _, rev := range revisions {
				if rev.State == protondriveapi.RevisionStateDraft {
					rev := rev
					if delErr := f.pacer.Call(func() (bool, error) {
						e := f.client.DeleteRevision(ctx, f.volumeID, linkID, rev.ID)
						return shouldRetry(ctx, e)
					}); delErr != nil {
						fs.Debugf(f, "prepareExistingFileRevision: delete draft revision %s: %v", rev.ID, delErr)
					}
				}
			}
		}
		if err := f.pacer.Call(func() (bool, error) {
			var e error
			revisionID, e = f.client.CreateRevision(ctx, f.volumeID, linkID)
			return shouldRetry(ctx, e)
		}); err != nil {
			return "", nil, nil, fmt.Errorf("prepareExistingFileRevision: create revision after draft cleanup: %w", err)
		}
	}

	return revisionID, sessionKey, nodeKR, nil
}

// uploadFile performs the full block-upload flow for an object.
// Returns the new linkID, XAttr common data, and error.
func (f *Fs) uploadFile(ctx context.Context, folderLinkID, leaf string, modTime time.Time, in io.Reader, existingLinkID string) (string, *protondriveapi.RevisionXAttrCommon, error) {
	parentKR, err := f.unlockLink(ctx, folderLinkID)
	if err != nil {
		return "", nil, fmt.Errorf("uploadFile: unlock parent: %w", err)
	}
	addrKR := f.client.GetPrimaryKR()

	// Determine MIME type from filename.
	mimeType := mime.TypeByExtension(filepath.Ext(leaf))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	if existingLinkID == "" {
		linkID, revisionID, sessionKey, nodeKR, err := f.prepareNewFileLink(ctx, folderLinkID, leaf, mimeType, parentKR, addrKR)
		if err != nil {
			return "", nil, fmt.Errorf("uploadFile: %w", err)
		}
		resultLinkID, attrs, uploadErr := f.uploadBlocks(ctx, linkID, revisionID, sessionKey, addrKR, nodeKR, modTime, in)
		if uploadErr != nil {
			// uploadBlocks already deleted the draft revision; also delete
			// the draft link itself so it doesn't pollute the parent folder.
			if delErr := f.pacer.Call(func() (bool, error) {
				e := f.client.DeleteDraftLinks(ctx, f.volumeID, []string{linkID})
				return shouldRetry(ctx, e)
			}); delErr != nil {
				fs.Debugf(f, "uploadFile: cleanup draft link %s: %v", linkID, delErr)
			}
			f.linkKRCache.Remove(linkID)
			return "", nil, fmt.Errorf("uploadFile: %w", uploadErr)
		}
		return resultLinkID, attrs, nil
	}

	revisionID, sessionKey, nodeKR, err := f.prepareExistingFileRevision(ctx, existingLinkID, addrKR)
	if err != nil {
		return "", nil, fmt.Errorf("uploadFile: %w", err)
	}
	return f.uploadBlocks(ctx, existingLinkID, revisionID, sessionKey, addrKR, nodeKR, modTime, in)
}

// uploadBlocks reads all data from in, splits into blocks, encrypts and uploads
// each block, then commits the revision.
func (f *Fs) uploadBlocks(ctx context.Context, linkID, revisionID string, sessionKey *pgpcrypto.SessionKey, addrKR, nodeKR *pgpcrypto.KeyRing, modTime time.Time, in io.Reader) (string, *protondriveapi.RevisionXAttrCommon, error) {
	// Clean up the draft revision on any failure path.
	// Use context.Background() so cleanup still runs even if ctx is cancelled.
	committed := false
	defer func() {
		if !committed {
			cleanupCtx := context.Background()
			if delErr := f.pacer.Call(func() (bool, error) {
				e := f.client.DeleteRevision(cleanupCtx, f.volumeID, linkID, revisionID)
				return shouldRetry(cleanupCtx, e)
			}); delErr != nil {
				fs.Debugf(f, "uploadBlocks: cleanup draft revision: %v", delErr)
			}
		}
	}()

	type encBlock struct {
		index     int
		encData   []byte
		encSig    string
		sha256B64 string
		blockSize int64
	}

	// Read and encrypt one block at a time to avoid loading the entire
	// file into memory as plaintext.
	sha1Hash := sha1.New()
	var encBlocks []encBlock
	var manifestHashData []byte
	buf := make([]byte, blockSize)
	blockIdx := 0
	for {
		n, readErr := io.ReadFull(in, buf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return "", nil, fmt.Errorf("uploadBlocks: read: %w", readErr)
		}
		if n == 0 && readErr == io.EOF && blockIdx > 0 {
			// Clean EOF with no data — all blocks already processed.
			break
		}
		chunk := buf[:n]
		if n == 0 {
			// Empty file: encode a single empty block.
			chunk = []byte{}
		}
		// Feed plaintext into SHA1 hasher before encryption.
		_, _ = sha1Hash.Write(chunk)
		blockIdx++
		encData, encSig, sha256B64, err := protondriveapi.EncryptBlock(chunk, sessionKey, addrKR, nodeKR)
		if err != nil {
			return "", nil, fmt.Errorf("uploadBlocks: encrypt block %d: %w", blockIdx, err)
		}
		encBlocks = append(encBlocks, encBlock{
			index:     blockIdx,
			encData:   encData,
			encSig:    encSig,
			sha256B64: sha256B64,
			blockSize: int64(n),
		})
		// Append raw SHA-256 bytes to manifest data
		hashBytes, err := base64.StdEncoding.DecodeString(sha256B64)
		if err != nil {
			return "", nil, fmt.Errorf("uploadBlocks: decode block hash: %w", err)
		}
		manifestHashData = append(manifestHashData, hashBytes...)
		if readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			// Last block (partial or exact block-sized last block).
			break
		}
	}
	// Note: encBlocks is never empty here. For an empty file io.ReadFull
	// returns n=0, err=io.EOF on the first iteration; the n==0 branch above
	// encrypts a single empty block before breaking out of the loop.

	// Get verification token for block upload
	var verificationCodeB64 string
	if err := f.pacer.Call(func() (bool, error) {
		var e error
		verificationCodeB64, e = f.client.GetVerificationCode(ctx, f.volumeID, linkID, revisionID)
		return shouldRetry(ctx, e)
	}); err != nil {
		return "", nil, fmt.Errorf("uploadBlocks: get verification code: %w", err)
	}
	verificationCode, err := base64.StdEncoding.DecodeString(verificationCodeB64)
	if err != nil {
		return "", nil, fmt.Errorf("uploadBlocks: decode verification code: %w", err)
	}

	// Request upload URLs.
	// The Verifier.Token for each block is: verificationCode XOR encryptedData[:len(verificationCode)]
	// (zero-padded if the encrypted data is shorter than the verification code).
	blockList := make([]protondriveapi.BlockUploadInfo, len(encBlocks))
	for i, b := range encBlocks {
		token := make([]byte, len(verificationCode))
		for j := range verificationCode {
			var encByte byte
			if j < len(b.encData) {
				encByte = b.encData[j]
			}
			token[j] = verificationCode[j] ^ encByte
		}
		blockList[i] = protondriveapi.BlockUploadInfo{
			Index:        b.index,
			EncSignature: b.encSig,
			Verifier:     protondriveapi.BlockVerifier{Token: base64.StdEncoding.EncodeToString(token)},
		}
	}

	var uploadLinks []protondriveapi.BlockUploadLink
	if err := f.pacer.Call(func() (bool, error) {
		var e error
		uploadLinks, e = f.client.RequestBlockUploadURLs(ctx, &protondriveapi.BlockUploadReq{
			AddressID:  f.addrID,
			VolumeID:   f.volumeID,
			LinkID:     linkID,
			RevisionID: revisionID,
			BlockList:  blockList,
		})
		return shouldRetry(ctx, e)
	}); err != nil {
		return "", nil, fmt.Errorf("uploadBlocks: request upload URLs: %w", err)
	}

	// Build index→URL map
	urlMap := make(map[int]protondriveapi.BlockUploadLink)
	for _, ul := range uploadLinks {
		urlMap[ul.Index] = ul
	}

	// Upload each block
	for _, b := range encBlocks {
		ul, ok := urlMap[b.index]
		if !ok {
			return "", nil, fmt.Errorf("uploadBlocks: no upload URL for block %d", b.index)
		}
		if err := f.pacer.Call(func() (bool, error) {
			e := f.client.UploadBlock(ctx, ul.BareURL, ul.Token, b.encData)
			return shouldRetry(ctx, e)
		}); err != nil {
			return "", nil, fmt.Errorf("uploadBlocks: upload block %d: %w", b.index, err)
		}
	}

	// Sign manifest
	manifestSig, err := protondriveapi.SignManifest(manifestHashData, addrKR)
	if err != nil {
		return "", nil, fmt.Errorf("uploadBlocks: sign manifest: %w", err)
	}

	// Build XAttr
	totalSize := int64(0)
	blockSizes := make([]int64, len(encBlocks))
	for i, b := range encBlocks {
		blockSizes[i] = b.blockSize
		totalSize += b.blockSize
	}

	// Compute SHA-1 of the full plaintext (for digests)
	sha1Digest := hex.EncodeToString(sha1Hash.Sum(nil))
	attrs := &protondriveapi.RevisionXAttrCommon{
		ModificationTime: modTime.UTC().Format(time.RFC3339),
		Size:             totalSize,
		BlockSizes:       blockSizes,
		Digests:          map[string]string{"SHA1": sha1Digest},
	}

	encXAttr, err := protondriveapi.EncryptXAttr(attrs, nodeKR, addrKR)
	if err != nil {
		return "", nil, fmt.Errorf("uploadBlocks: encrypt xattr: %w", err)
	}

	// Commit revision
	if err := f.pacer.Call(func() (bool, error) {
		e := f.client.CommitRevision(ctx, f.volumeID, linkID, revisionID, &protondriveapi.CommitRevisionReq{
			ManifestSignature: manifestSig,
			SignatureAddress:  f.addrEmail,
			XAttr:             encXAttr,
			State:             protondriveapi.RevisionStateActive,
		})
		return shouldRetry(ctx, e)
	}); err != nil {
		return "", nil, fmt.Errorf("uploadBlocks: commit revision: %w", err)
	}

	committed = true
	return linkID, attrs, nil
}
