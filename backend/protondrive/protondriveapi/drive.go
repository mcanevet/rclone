package protondriveapi

// drive.go contains all Proton Drive API method implementations on ProtonClient:
// share operations, link CRUD, file revision lifecycle, block upload/download,
// move/rename, trash, hash checks, share URLs, and events.
//
// User/address/key lookups and SRP-moduli are handled by the embedded
// *protonapi.ProtonClient (promoted methods, no wrappers needed here).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
)

// ---- Share -----------------------------------------------------------------

// GetFilesShare returns the main files share for the authenticated user.
func (c *ProtonClient) GetFilesShare(ctx context.Context) (*FilesShareResp, error) {
	var resp FilesShareResp
	if err := c.CallJSON(ctx, "GET", "/drive/v2/shares/my-files", nil, &resp, false); err != nil {
		return nil, fmt.Errorf("getFilesShare: %w", err)
	}
	return &resp, nil
}

// ---- Links -----------------------------------------------------------------

// ErrPartialLinks is returned (wrapped) by BatchGetLinks when the server
// successfully processes the request but reports that some link IDs could not
// be returned. The partial results are still returned alongside this error;
// callers should check errors.Is(err, ErrPartialLinks) to decide whether to
// use the partial slice or treat the call as a hard failure.
var ErrPartialLinks = fmt.Errorf("server could not return all requested links")

// BatchGetLinks fetches metadata for a batch of link IDs.
// The API accepts at most 100 IDs per request; if linkIDs exceeds that,
// BatchGetLinks automatically splits into multiple requests and merges results.
//
// If the server returns partial results (some link IDs in the Failed field),
// the partial slice is returned together with an error wrapping ErrPartialLinks.
func (c *ProtonClient) BatchGetLinks(ctx context.Context, volumeID string, linkIDs []string) ([]LinkWrapper, error) {
	const maxPerReq = 100
	if len(linkIDs) <= maxPerReq {
		var resp LinksResp
		if err := c.CallJSON(ctx, "POST", fmt.Sprintf("/drive/v2/volumes/%s/links", volumeID),
			&BatchLinksReq{LinkIDs: linkIDs}, &resp, false); err != nil {
			return nil, fmt.Errorf("batchGetLinks: %w", err)
		}
		if len(resp.Failed) > 0 {
			return resp.Links, fmt.Errorf("batchGetLinks: %w (failed: %v)", ErrPartialLinks, resp.Failed)
		}
		return resp.Links, nil
	}
	// Chunk into maxPerReq-sized slices and merge.
	var all []LinkWrapper
	var allFailed []string
	for len(linkIDs) > 0 {
		size := maxPerReq
		if size > len(linkIDs) {
			size = len(linkIDs)
		}
		batch := linkIDs[:size]
		linkIDs = linkIDs[size:]
		var resp LinksResp
		if err := c.CallJSON(ctx, "POST", fmt.Sprintf("/drive/v2/volumes/%s/links", volumeID),
			&BatchLinksReq{LinkIDs: batch}, &resp, false); err != nil {
			return nil, fmt.Errorf("batchGetLinks: %w", err)
		}
		allFailed = append(allFailed, resp.Failed...)
		all = append(all, resp.Links...)
	}
	var partialErr error
	if len(allFailed) > 0 {
		partialErr = fmt.Errorf("batchGetLinks: %w (failed: %v)", ErrPartialLinks, allFailed)
	}
	return all, partialErr
}

// WalkFolderChildren streams children of a folder in batches of up to 100,
// calling fn for each batch. Pagination and BatchGetLinks chunking are handled
// internally. If fn returns a non-nil error the walk stops immediately and
// that error is returned unwrapped to the caller so it can distinguish
// sentinel values (e.g. errFound) from real errors.
func (c *ProtonClient) WalkFolderChildren(ctx context.Context, volumeID, folderLinkID string, fn func([]LinkWrapper) error) error {
	const batchSize = 100
	// idBuf accumulates link IDs from the children endpoint until we have a
	// full batch (batchSize) to pass to BatchGetLinks, or until the last page.
	var idBuf []string
	anchorID := ""
	for {
		params := url.Values{}
		if anchorID != "" {
			params.Set("AnchorID", anchorID)
		}
		apiPath := fmt.Sprintf("/drive/v2/volumes/%s/folders/%s/children", volumeID, folderLinkID)
		if len(params) > 0 {
			apiPath += "?" + params.Encode()
		}
		var resp FolderChildrenResp
		if err := c.CallJSON(ctx, "GET", apiPath, nil, &resp, false); err != nil {
			return fmt.Errorf("walkFolderChildren: %w", err)
		}
		idBuf = append(idBuf, resp.LinkIDs...)
		lastPage := !resp.More

		// Flush complete batches whenever we have enough IDs, or on the last page.
		for len(idBuf) >= batchSize || (lastPage && len(idBuf) > 0) {
			size := batchSize
			if size > len(idBuf) {
				size = len(idBuf)
			}
			batch := idBuf[:size]
			idBuf = idBuf[size:]

			links, err := c.BatchGetLinks(ctx, volumeID, batch)
			if err != nil && !errors.Is(err, ErrPartialLinks) {
				return fmt.Errorf("walkFolderChildren batchGetLinks: %w", err)
			}
			// ErrPartialLinks: some links are missing but we still deliver what
			// the server returned so the walk can continue with partial data.
			if err := fn(links); err != nil {
				return err // caller's sentinel — do not wrap
			}
		}

		if lastPage {
			break
		}
		anchorID = resp.AnchorID
	}
	return nil
}

// ListFolderChildren lists all children of a folder, following pagination.
// It returns LinkWrapper objects (fetched in batches via WalkFolderChildren).
// For streaming access to large directories prefer WalkFolderChildren directly.
func (c *ProtonClient) ListFolderChildren(ctx context.Context, volumeID, folderLinkID string) ([]LinkWrapper, error) {
	var all []LinkWrapper
	if err := c.WalkFolderChildren(ctx, volumeID, folderLinkID, func(batch []LinkWrapper) error {
		all = append(all, batch...)
		return nil
	}); err != nil {
		return nil, err
	}
	return all, nil
}

// ---- Folder ----------------------------------------------------------------

// CreateFolder creates a new folder and returns its linkID.
func (c *ProtonClient) CreateFolder(ctx context.Context, volumeID string, req *CreateFolderReq) (string, error) {
	var resp CreateFolderResp
	if err := c.CallJSON(ctx, "POST", fmt.Sprintf("/drive/v2/volumes/%s/folders", volumeID),
		req, &resp, false); err != nil {
		return "", fmt.Errorf("createFolder: %w", err)
	}
	return resp.Folder.ID, nil
}

// ---- File / Revision -------------------------------------------------------

// CreateFile creates a new file draft and returns (linkID, revisionID).
// If the server returns Code 2500 (name conflict), the returned error is
// *CreateFileConflictError so callers can inspect ConflictLinkID /
// ConflictDraftRevisionID and decide how to proceed.
func (c *ProtonClient) CreateFile(ctx context.Context, volumeID string, req *CreateFileReq) (string, string, error) {
	path := fmt.Sprintf("/drive/v2/volumes/%s/files", volumeID)
	statusCode, body, err := c.CallRaw(ctx, "POST", path, req)
	if err != nil {
		return "", "", fmt.Errorf("createFile: %w", err)
	}

	if statusCode >= 200 && statusCode <= 299 {
		var fileResp CreateFileResp
		if decErr := json.Unmarshal(body, &fileResp); decErr != nil {
			return "", "", fmt.Errorf("createFile: decode response: %w", decErr)
		}
		return fileResp.File.ID, fileResp.File.RevisionID, nil
	}

	// Non-2xx: try Code 2500 (name conflict) before falling back to generic.
	var conflictResp CreateFileConflictError
	if decErr := json.Unmarshal(body, &conflictResp); decErr == nil && conflictResp.Code == CodeNameConflict {
		return "", "", &conflictResp
	}
	var apiErr Error
	if decErr := json.Unmarshal(body, &apiErr); decErr == nil && apiErr.Message != "" {
		return "", "", &apiErr
	}
	return "", "", fmt.Errorf("createFile: HTTP %d", statusCode)
}

// CreateRevision creates a new draft revision for an existing file.
func (c *ProtonClient) CreateRevision(ctx context.Context, volumeID, fileLinkID string) (string, error) {
	var resp CreateRevisionResp
	if err := c.CallJSON(ctx, "POST",
		fmt.Sprintf("/drive/v2/volumes/%s/files/%s/revisions", volumeID, fileLinkID),
		&struct{}{}, &resp, false); err != nil {
		return "", fmt.Errorf("createRevision: %w", err)
	}
	return resp.Revision.ID, nil
}

// GetRevision returns a revision (including its blocks).
func (c *ProtonClient) GetRevision(ctx context.Context, volumeID, fileLinkID, revisionID string) (*Revision, error) {
	var resp GetRevisionResp
	if err := c.CallJSON(ctx, "GET",
		fmt.Sprintf("/drive/v2/volumes/%s/files/%s/revisions/%s", volumeID, fileLinkID, revisionID),
		nil, &resp, false); err != nil {
		return nil, fmt.Errorf("getRevision: %w", err)
	}
	return &resp.Revision, nil
}

// ListRevisions returns all revisions for a file (including draft ones).
func (c *ProtonClient) ListRevisions(ctx context.Context, volumeID, fileLinkID string) ([]Revision, error) {
	var resp ListRevisionsResp
	if err := c.CallJSON(ctx, "GET",
		fmt.Sprintf("/drive/v2/volumes/%s/files/%s/revisions", volumeID, fileLinkID),
		nil, &resp, false); err != nil {
		return nil, fmt.Errorf("listRevisions: %w", err)
	}
	return resp.Revisions, nil
}

// CommitRevision commits a draft revision to active state.
func (c *ProtonClient) CommitRevision(ctx context.Context, volumeID, fileLinkID, revisionID string, req *CommitRevisionReq) error {
	if err := c.CallJSONNoResp(ctx, "PUT",
		fmt.Sprintf("/drive/v2/volumes/%s/files/%s/revisions/%s", volumeID, fileLinkID, revisionID),
		req); err != nil {
		return fmt.Errorf("commitRevision: %w", err)
	}
	return nil
}

// DeleteRevision deletes a draft revision (cleanup on upload failure).
func (c *ProtonClient) DeleteRevision(ctx context.Context, volumeID, fileLinkID, revisionID string) error {
	if err := c.CallJSONNoResp(ctx, "DELETE",
		fmt.Sprintf("/drive/v2/volumes/%s/files/%s/revisions/%s", volumeID, fileLinkID, revisionID),
		nil); err != nil {
		return fmt.Errorf("deleteRevision: %w", err)
	}
	return nil
}

// ---- Block upload ----------------------------------------------------------

// GetVerificationCode fetches the verification token for a draft revision.
// Endpoint: GET /drive/v2/volumes/{volumeID}/links/{linkID}/revisions/{revisionID}/verification
func (c *ProtonClient) GetVerificationCode(ctx context.Context, volumeID, linkID, revisionID string) (string, error) {
	var resp VerificationResp
	if err := c.CallJSON(ctx, "GET",
		fmt.Sprintf("/drive/v2/volumes/%s/links/%s/revisions/%s/verification", volumeID, linkID, revisionID),
		nil, &resp, false); err != nil {
		return "", fmt.Errorf("getVerificationCode: %w", err)
	}
	return resp.VerificationCode, nil
}

// RequestBlockUploadURLs requests signed upload URLs for a batch of blocks.
func (c *ProtonClient) RequestBlockUploadURLs(ctx context.Context, req *BlockUploadReq) ([]BlockUploadLink, error) {
	var resp BlockUploadResp
	if err := c.CallJSON(ctx, "POST", "/drive/blocks", req, &resp, false); err != nil {
		return nil, fmt.Errorf("requestBlockUploadURLs: %w", err)
	}
	return resp.UploadLinks, nil
}

// UploadBlock uploads an encrypted block to block storage using its signed URL.
// Block storage uses a POST multipart/form-data with a "Block" field and pm-storage-token header.
func (c *ProtonClient) UploadBlock(ctx context.Context, bareURL, token string, data []byte) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("Block", "blob")
	if err != nil {
		return fmt.Errorf("uploadBlock: create form file: %w", err)
	}
	if _, err = fw.Write(data); err != nil {
		return fmt.Errorf("uploadBlock: write form data: %w", err)
	}
	if err = mw.Close(); err != nil {
		return fmt.Errorf("uploadBlock: close multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", bareURL, &body)
	if err != nil {
		return fmt.Errorf("uploadBlock: build request: %w", err)
	}
	req.Header.Set("pm-storage-token", token)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("uploadBlock: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		blockErr := fmt.Errorf("uploadBlock: HTTP %d: %s", resp.StatusCode, buf.String())
		if resp.StatusCode >= 500 {
			return &RetryableError{Err: blockErr}
		}
		return blockErr
	}
	// Drain the response body to allow the underlying TCP connection to be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// DownloadBlock downloads an encrypted block from block storage.
func (c *ProtonClient) DownloadBlock(ctx context.Context, bareURL, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", bareURL, nil)
	if err != nil {
		return nil, fmt.Errorf("downloadBlock: build request: %w", err)
	}
	req.Header.Set("pm-storage-token", token)

	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloadBlock: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		blockErr := fmt.Errorf("downloadBlock: HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 500 {
			return nil, &RetryableError{Err: blockErr}
		}
		return nil, blockErr
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, fmt.Errorf("downloadBlock: read body: %w", err)
	}
	return buf.Bytes(), nil
}

// ---- Move / Rename ---------------------------------------------------------

// RenameLink renames a link in place.
func (c *ProtonClient) RenameLink(ctx context.Context, volumeID, linkID string, req *MoveLinkReq) error {
	if err := c.CallJSONNoResp(ctx, "PUT",
		fmt.Sprintf("/drive/v2/volumes/%s/links/%s/rename", volumeID, linkID),
		req); err != nil {
		return fmt.Errorf("renameLink: %w", err)
	}
	return nil
}

// MoveLink moves a link to a different parent.
func (c *ProtonClient) MoveLink(ctx context.Context, volumeID, linkID string, req *MoveLinkReq) error {
	if err := c.CallJSONNoResp(ctx, "PUT",
		fmt.Sprintf("/drive/v2/volumes/%s/links/%s/move", volumeID, linkID),
		req); err != nil {
		return fmt.Errorf("moveLink: %w", err)
	}
	return nil
}

// ---- Trash -----------------------------------------------------------------

// TrashLinks moves the given link IDs to trash.
// All links are attempted; per-link failures are collected and returned as a
// joined error so that successful trashes are not lost.
func (c *ProtonClient) TrashLinks(ctx context.Context, volumeID string, linkIDs []string) error {
	var resp TrashLinksResp
	if err := c.CallJSON(ctx, "POST",
		fmt.Sprintf("/drive/v2/volumes/%s/trash_multiple", volumeID),
		&TrashLinksReq{LinkIDs: linkIDs}, &resp, false); err != nil {
		return fmt.Errorf("trashLinks: %w", err)
	}
	// Collect per-link failures; the server may return HTTP 200 even when
	// individual links failed (partial failure).
	var errs []error
	for _, r := range resp.Responses {
		if r.Response.Code != CodeSuccess {
			errs = append(errs, fmt.Errorf("link %s failed with code %d", r.LinkID, r.Response.Code))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("trashLinks: %w", errors.Join(errs...))
	}
	return nil
}

// DeleteDraftLinks permanently deletes draft (never-committed) links,
// bypassing trash. Only works for draft links — use TrashLinks for committed files.
// Endpoint: POST /drive/v2/volumes/{volumeID}/delete_multiple
func (c *ProtonClient) DeleteDraftLinks(ctx context.Context, volumeID string, linkIDs []string) error {
	if err := c.CallJSONNoResp(ctx, "POST",
		fmt.Sprintf("/drive/v2/volumes/%s/delete_multiple", volumeID),
		&struct {
			LinkIDs []string `json:"LinkIDs"`
		}{LinkIDs: linkIDs}); err != nil {
		return fmt.Errorf("deleteDraftLinks: %w", err)
	}
	return nil
}

// EmptyTrash empties the trash for a volume.
func (c *ProtonClient) EmptyTrash(ctx context.Context, volumeID string) error {
	if err := c.CallJSONNoResp(ctx, "DELETE",
		fmt.Sprintf("/drive/volumes/%s/trash", volumeID),
		nil); err != nil {
		return fmt.Errorf("emptyTrash: %w", err)
	}
	return nil
}

// ---- Hash availability -----------------------------------------------------

// CheckAvailableHashes checks which name hashes are available (not yet used).
func (c *ProtonClient) CheckAvailableHashes(ctx context.Context, volumeID, folderLinkID string, hashes []string) (*CheckHashesResp, error) {
	var resp CheckHashesResp
	if err := c.CallJSON(ctx, "POST",
		fmt.Sprintf("/drive/v2/volumes/%s/links/%s/checkAvailableHashes", volumeID, folderLinkID),
		&CheckHashesReq{Hashes: hashes}, &resp, false); err != nil {
		return nil, fmt.Errorf("checkAvailableHashes: %w", err)
	}
	return &resp, nil
}

// ---- Standard share --------------------------------------------------------

// CreateStandardShare creates a new non-main share rooted at linkID and
// returns the new shareID.
func (c *ProtonClient) CreateStandardShare(ctx context.Context, volumeID string, req *CreateStandardShareReq) (string, error) {
	var resp CreateStandardShareResp
	if err := c.CallJSON(ctx, "POST",
		fmt.Sprintf("/drive/volumes/%s/shares", volumeID),
		req, &resp, false); err != nil {
		return "", fmt.Errorf("createStandardShare: %w", err)
	}
	return resp.Share.ID, nil
}

// FindShareIDForLink looks up the existing non-primary share for linkID by
// paging through GET /drive/v2/volumes/{volumeID}/shares and returning the
// first entry whose LinkID matches. Returns "" if none is found.
func (c *ProtonClient) FindShareIDForLink(ctx context.Context, volumeID, linkID string) (string, error) {
	anchor := ""
	for {
		path := fmt.Sprintf("/drive/v2/volumes/%s/shares", volumeID)
		if anchor != "" {
			path += "?AnchorID=" + url.QueryEscape(anchor)
		}
		var resp ListVolumeSharesResp
		if err := c.CallJSON(ctx, "GET", path, nil, &resp, false); err != nil {
			return "", fmt.Errorf("findShareIDForLink: list: %w", err)
		}
		for _, l := range resp.Links {
			if l.LinkID == linkID {
				return l.ShareID, nil
			}
		}
		if !resp.More || resp.AnchorID == "" {
			break
		}
		anchor = resp.AnchorID
	}
	return "", nil
}

// GetShare returns the share metadata (key, passphrase, etc.) for shareID.
func (c *ProtonClient) GetShare(ctx context.Context, shareID string) (*Share, error) {
	var resp ShareResp
	if err := c.CallJSON(ctx, "GET",
		fmt.Sprintf("/drive/shares/%s", shareID),
		nil, &resp, false); err != nil {
		return nil, fmt.Errorf("getShare: %w", err)
	}
	return &resp.Share, nil
}

// ---- Share URLs (public links) ---------------------------------------------

// ListShareURLs returns all ShareURL objects for the given share.
func (c *ProtonClient) ListShareURLs(ctx context.Context, shareID string) ([]ShareURLData, error) {
	var resp ListShareURLsResp
	if err := c.CallJSON(ctx, "GET",
		fmt.Sprintf("/drive/shares/%s/urls", shareID),
		nil, &resp, false); err != nil {
		return nil, fmt.Errorf("listShareURLs: %w", err)
	}
	return resp.ShareURLs, nil
}

// CreateShareURL creates a new public-link ShareURL for the given share.
func (c *ProtonClient) CreateShareURL(ctx context.Context, shareID string, req *CreateShareURLReq) (*ShareURLData, error) {
	var resp CreateShareURLResp
	if err := c.CallJSON(ctx, "POST",
		fmt.Sprintf("/drive/shares/%s/urls", shareID),
		req, &resp, false); err != nil {
		return nil, fmt.Errorf("createShareURL: %w", err)
	}
	return &resp.ShareURL, nil
}

// DeleteShareURLs deletes one or more ShareURLs for the given share.
func (c *ProtonClient) DeleteShareURLs(ctx context.Context, shareID string, shareURLIDs []string) error {
	if err := c.CallJSONNoResp(ctx, "POST",
		fmt.Sprintf("/drive/shares/%s/urls/delete_multiple", shareID),
		&DeleteShareURLsReq{ShareURLIDs: shareURLIDs}); err != nil {
		return fmt.Errorf("deleteShareURLs: %w", err)
	}
	return nil
}

// ---- Events ----------------------------------------------------------------

// GetLatestEventID returns the ID of the latest event for the volume.
func (c *ProtonClient) GetLatestEventID(ctx context.Context, volumeID string) (string, error) {
	var resp LatestEventResp
	if err := c.CallJSON(ctx, "GET",
		fmt.Sprintf("/drive/volumes/%s/events/latest", volumeID),
		nil, &resp, false); err != nil {
		return "", fmt.Errorf("getLatestEventID: %w", err)
	}
	return resp.EventID, nil
}

// PollEvents fetches events since the given event ID.
func (c *ProtonClient) PollEvents(ctx context.Context, volumeID, eventID string) (*DriveEventResp, error) {
	var resp DriveEventResp
	if err := c.CallJSON(ctx, "GET",
		fmt.Sprintf("/drive/v2/volumes/%s/events/%s", volumeID, eventID),
		nil, &resp, false); err != nil {
		return nil, fmt.Errorf("pollEvents: %w", err)
	}
	return &resp, nil
}
