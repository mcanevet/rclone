package protondriveapi

// api_client.go contains the Proton Drive API client: the Client interface,
// the ProtonClient struct (which embeds *protonapi.ProtonClient for all
// generic session/auth/user logic), and its constructor.
//
// It has zero dependency on rclone internals.

import (
	"context"
	"net/http"

	"github.com/rclone/rclone/backend/protondrive/protonapi"
)

// Client is the interface satisfied by ProtonClient. It covers every method
// called by the parent protondrive package, enabling the package to be tested
// with a mock implementation without depending on a live Proton API.
type Client interface {
	// Embed the generic session interface (auth, credentials, keyrings,
	// user/address/keysalt/SRP-moduli endpoints).
	protonapi.SessionClient

	// Share
	GetFilesShare(ctx context.Context) (*FilesShareResp, error)
	GetShare(ctx context.Context, shareID string) (*Share, error)
	CreateStandardShare(ctx context.Context, volumeID string, req *CreateStandardShareReq) (string, error)
	FindShareIDForLink(ctx context.Context, volumeID, linkID string) (string, error)

	// Links
	BatchGetLinks(ctx context.Context, volumeID string, linkIDs []string) ([]LinkWrapper, error)
	ListFolderChildren(ctx context.Context, volumeID, folderLinkID string) ([]LinkWrapper, error)
	// WalkFolderChildren streams children of a folder in batches of up to 100,
	// calling fn for each batch. If fn returns an error, the walk stops
	// immediately and that error is returned to the caller (with no wrapping).
	WalkFolderChildren(ctx context.Context, volumeID, folderLinkID string, fn func([]LinkWrapper) error) error

	// Folder
	CreateFolder(ctx context.Context, volumeID string, req *CreateFolderReq) (string, error)

	// File / Revision
	CreateFile(ctx context.Context, volumeID string, req *CreateFileReq) (string, string, error)
	CreateRevision(ctx context.Context, volumeID, fileLinkID string) (string, error)
	GetRevision(ctx context.Context, volumeID, fileLinkID, revisionID string) (*Revision, error)
	ListRevisions(ctx context.Context, volumeID, fileLinkID string) ([]Revision, error)
	CommitRevision(ctx context.Context, volumeID, fileLinkID, revisionID string, req *CommitRevisionReq) error
	DeleteRevision(ctx context.Context, volumeID, fileLinkID, revisionID string) error

	// Block upload / download
	GetVerificationCode(ctx context.Context, volumeID, linkID, revisionID string) (string, error)
	RequestBlockUploadURLs(ctx context.Context, req *BlockUploadReq) ([]BlockUploadLink, error)
	UploadBlock(ctx context.Context, bareURL, token string, data []byte) error
	DownloadBlock(ctx context.Context, bareURL, token string) ([]byte, error)

	// Move / Rename
	RenameLink(ctx context.Context, volumeID, linkID string, req *MoveLinkReq) error
	MoveLink(ctx context.Context, volumeID, linkID string, req *MoveLinkReq) error

	// Trash
	TrashLinks(ctx context.Context, volumeID string, linkIDs []string) error
	DeleteDraftLinks(ctx context.Context, volumeID string, linkIDs []string) error
	EmptyTrash(ctx context.Context, volumeID string) error

	// Hashes
	CheckAvailableHashes(ctx context.Context, volumeID, folderLinkID string, hashes []string) (*CheckHashesResp, error)

	// Share URLs
	ListShareURLs(ctx context.Context, shareID string) ([]ShareURLData, error)
	CreateShareURL(ctx context.Context, shareID string, req *CreateShareURLReq) (*ShareURLData, error)
	DeleteShareURLs(ctx context.Context, shareID string, shareURLIDs []string) error

	// Events
	GetLatestEventID(ctx context.Context, volumeID string) (string, error)
	PollEvents(ctx context.Context, volumeID, eventID string) (*DriveEventResp, error)
}

// Ensure ProtonClient implements Client at compile time.
var _ Client = (*ProtonClient)(nil)

// ProtonClient holds authentication state and an *http.Client for the
// Proton Drive API. It embeds *protonapi.ProtonClient for all generic
// session/auth/user logic and adds Drive-specific methods on top.
type ProtonClient struct {
	*protonapi.ProtonClient
}

// NewProtonClient creates a ProtonClient that talks to apiURL.
// If apiURL is empty, protonapi.DefaultAPIURL is used.
// If appVersion is empty, protonapi.DefaultAppVersion is used.
func NewProtonClient(httpClient *http.Client, apiURL, appVersion string) (*ProtonClient, error) {
	base, err := protonapi.NewProtonClient(httpClient, apiURL, appVersion)
	if err != nil {
		return nil, err
	}
	return &ProtonClient{ProtonClient: base}, nil
}
