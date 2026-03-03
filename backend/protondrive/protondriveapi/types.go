// Package protondriveapi contains type definitions and the API client for
// the Proton Drive REST API. It has zero dependency on rclone internals.
//
// Generic Proton API types (auth, user, address, key salts, errors) are
// provided as type aliases from protonapi so callers in the parent package
// do not need to import both packages.
//
// Reference: https://github.com/ProtonDriveApps/sdk
package protondriveapi

import "github.com/rclone/rclone/backend/protondrive/protonapi"

// ---- Aliases for generic Proton types from protonapi -----------------------
// Using type aliases (=) means these are the *same* type, so the interface
// embedding in Client is satisfied without any conversion.

// RetryableError — alias of protonapi.RetryableError.
type RetryableError = protonapi.RetryableError

// Error — alias of protonapi.Error.
type Error = protonapi.Error

// Response — alias of protonapi.Response.
type Response = protonapi.Response

// Auth — alias of protonapi.Auth.
type Auth = protonapi.Auth

// AuthRefreshResp — alias of protonapi.AuthRefreshResp.
type AuthRefreshResp = protonapi.AuthRefreshResp

// User — alias of protonapi.User.
type User = protonapi.User

// UserKey — alias of protonapi.UserKey.
type UserKey = protonapi.UserKey

// AddressKey — alias of protonapi.AddressKey.
type AddressKey = protonapi.AddressKey

// Address — alias of protonapi.Address.
type Address = protonapi.Address

// KeySalt — alias of protonapi.KeySalt.
type KeySalt = protonapi.KeySalt

// SRPModuliResp — alias of protonapi.SRPModuliResp.
type SRPModuliResp = protonapi.SRPModuliResp

// ---- Named API response codes ----------------------------------------------

const (
	// CodeSuccess is the standard Proton API success code.
	CodeSuccess = 1000
	// CodeMaybeOutdated is returned when the server rejects a request because
	// the client state is considered outdated (e.g. wrong session key on move).
	CodeMaybeOutdated = 2000
	// CodeNameConflict is returned by CreateFile when a link with the same
	// name hash already exists in the target folder.
	CodeNameConflict = 2500
	// CodeStaleRevision is returned by CreateRevision when the link already
	// has a draft revision that must be cleaned up first.
	CodeStaleRevision = 2501
)

// ---- Drive-specific conflict error -----------------------------------------

// CreateFileConflictDetails holds the Details payload of a Code 2500 error
// from createFile (ConflictErrorDetailsDto in driveTypes.ts).
type CreateFileConflictDetails struct {
	ConflictLinkID          string  `json:"ConflictLinkID"`
	ConflictRevisionID      *string `json:"ConflictRevisionID"`
	ConflictDraftRevisionID *string `json:"ConflictDraftRevisionID"`
	ConflictDraftClientUID  *string `json:"ConflictDraftClientUID"`
}

// CreateFileConflictError is returned (as a typed error) by createFile when
// the server responds with Code 2500 (file with same name already exists).
type CreateFileConflictError struct {
	Code    int                       `json:"Code"`
	Message string                    `json:"Error"`
	Details CreateFileConflictDetails `json:"Details"`
}

func (e *CreateFileConflictError) Error() string { return e.Message }

// ---- Volume ----------------------------------------------------------------

// LinkType distinguishes folders from files.
type LinkType int

const (
	// LinkTypeFolder is a folder node.
	LinkTypeFolder LinkType = 1
	// LinkTypeFile is a file node.
	LinkTypeFile LinkType = 2
)

// ---- Share -----------------------------------------------------------------

// ShareType is the type of a share.
type ShareType int

const (
	// ShareTypeMain is the main personal share.
	ShareTypeMain ShareType = 1
)

// ShareFlag is a bit-field of share flags.
type ShareFlag int

const (
	// ShareFlagPrimary marks the primary share.
	ShareFlagPrimary ShareFlag = 1
)

// Share represents a Proton Drive share.
type Share struct {
	ShareID             string    `json:"ShareID"`
	VolumeID            string    `json:"VolumeID"`
	LinkID              string    `json:"LinkID"`
	Type                ShareType `json:"Type"`
	Flags               ShareFlag `json:"Flags"`
	Creator             string    `json:"Creator"`
	CreatorEmail        string    `json:"CreatorEmail"`
	AddressID           string    `json:"AddressID"`
	Key                 string    `json:"Key"`                 // armored private key
	Passphrase          string    `json:"Passphrase"`          // armored PGP message
	PassphraseSignature string    `json:"PassphraseSignature"` // armored detached signature
}

// ShareResp is the response from GET /drive/shares/{shareID}.
// The API returns share fields at the root level (not nested under "Share"),
// so Share is embedded anonymously so encoding/json decodes fields directly.
type ShareResp struct {
	Response
	Share // anonymous embed → fields decoded at root level
}

// FilesShareVolume is the volume section in FilesShareResp.
type FilesShareVolume struct {
	VolumeID string `json:"VolumeID"`
}

// FilesShareLinkCore is the inner Link object within the Link wrapper.
type FilesShareLinkCore struct {
	LinkID string `json:"LinkID"`
}

// FilesShareLink is the link wrapper within FilesShareResp.
type FilesShareLink struct {
	Link FilesShareLinkCore `json:"Link"`
}

// FilesShareResp is the response from GET /drive/v2/shares/my-files.
// Shape: { Volume: { VolumeID }, Share: { ShareID, Key, Passphrase, ... }, Link: { Link: { LinkID } } }
type FilesShareResp struct {
	Response
	Volume FilesShareVolume `json:"Volume"`
	Share  Share            `json:"Share"`
	Link   FilesShareLink   `json:"Link"`
}

// ---- Link ------------------------------------------------------------------

// LinkState is the state of a Link.
type LinkState int

const (
	// LinkStateDraft means the file is in draft (incomplete upload).
	LinkStateDraft LinkState = 0
	// LinkStateActive means the file/folder is active.
	LinkStateActive LinkState = 1
	// LinkStateTrashed means the file/folder is in trash.
	LinkStateTrashed LinkState = 2
	// LinkStateDeleted means the file/folder has been permanently deleted.
	LinkStateDeleted LinkState = 3
)

// ---- Nested link structures from v2 batch endpoints -----------------------

// LinkCore is the core link metadata returned in the nested "Link" sub-object
// from POST /drive/v2/volumes/{volumeID}/links.
type LinkCore struct {
	LinkID       string    `json:"LinkID"`
	ParentLinkID string    `json:"ParentLinkID"`
	Type         LinkType  `json:"Type"`
	State        LinkState `json:"State"`

	Name               string `json:"Name"`
	NameSignatureEmail string `json:"NameSignatureEmail"`
	NameHash           string `json:"NameHash"`

	CreateTime int64 `json:"CreateTime"`
	ModifyTime int64 `json:"ModifyTime"`

	NodeKey                 string `json:"NodeKey"`
	NodePassphrase          string `json:"NodePassphrase"`
	NodePassphraseSignature string `json:"NodePassphraseSignature"`
	SignatureEmail          string `json:"SignatureEmail"`
}

// ActiveRevisionData is the nested active revision inside FileData.
type ActiveRevisionData struct {
	RevisionID     string `json:"RevisionID"`
	CreateTime     int64  `json:"CreateTime"`
	EncryptedSize  int64  `json:"EncryptedSize"`
	SignatureEmail string `json:"SignatureEmail"`
	XAttr          string `json:"XAttr,omitempty"`
}

// FileData contains file-specific fields from the nested "File" sub-object.
type FileData struct {
	ContentKeyPacket          string              `json:"ContentKeyPacket"`
	ContentKeyPacketSignature string              `json:"ContentKeyPacketSignature"`
	MediaType                 string              `json:"MediaType"`
	TotalEncryptedSize        int64               `json:"TotalEncryptedSize"`
	ActiveRevision            *ActiveRevisionData `json:"ActiveRevision,omitempty"`
}

// FolderData contains folder-specific fields from the nested "Folder" sub-object.
type FolderData struct {
	NodeHashKey string `json:"NodeHashKey"`
	XAttr       string `json:"XAttr,omitempty"`
}

// LinkWrapper is the per-entry shape returned by POST /drive/v2/volumes/{volumeID}/links.
type LinkWrapper struct {
	Link   LinkCore    `json:"Link"`
	File   *FileData   `json:"File,omitempty"`
	Folder *FolderData `json:"Folder,omitempty"`
}

// LinksResp is the response from POST /drive/v2/volumes/{volumeID}/links (batch).
type LinksResp struct {
	Response
	Links  []LinkWrapper `json:"Links"`
	Failed []string      `json:"Failed,omitempty"`
}

// FolderChildrenResp is the response from GET .../folders/{linkID}/children.
// The API returns only IDs; callers must then batch-fetch via batchGetLinks.
type FolderChildrenResp struct {
	Response
	LinkIDs  []string `json:"LinkIDs"`
	AnchorID string   `json:"AnchorID,omitempty"`
	More     bool     `json:"More"`
}

// ---- Folder ----------------------------------------------------------------

// CreateNodeReq holds the fields common to both CreateFolderReq and
// CreateFileReq: the parent link, encrypted name/hash, and the node key
// material. Both folder and file creation requests embed this struct.
type CreateNodeReq struct {
	ParentLinkID            string `json:"ParentLinkID"`
	Name                    string `json:"Name"`
	Hash                    string `json:"Hash"`
	NodeKey                 string `json:"NodeKey"`
	NodePassphrase          string `json:"NodePassphrase"`
	NodePassphraseSignature string `json:"NodePassphraseSignature"`
	SignatureEmail          string `json:"SignatureEmail"`
}

// CreateFolderReq is the body for POST /drive/v2/volumes/{volumeID}/folders.
type CreateFolderReq struct {
	CreateNodeReq
	NodeHashKey string `json:"NodeHashKey"` // encrypted HMAC key
}

// CreateFolderResp is the response from POST .../folders.
type CreateFolderResp struct {
	Response
	Folder struct {
		ID string `json:"ID"`
	} `json:"Folder"`
}

// ---- File / Revision -------------------------------------------------------

// RevisionState is the state of a file revision.
type RevisionState int

const (
	// RevisionStateDraft means the revision is not yet committed.
	RevisionStateDraft RevisionState = 0
	// RevisionStateActive means the revision is the active revision.
	RevisionStateActive RevisionState = 1
	// RevisionStateObsolete means the revision has been superseded.
	RevisionStateObsolete RevisionState = 2
)

// Revision represents one revision of a file.
type Revision struct {
	ID                string        `json:"ID"`
	State             RevisionState `json:"State"`
	Size              int64         `json:"Size"`
	ManifestSignature string        `json:"ManifestSignature"`
	SignatureEmail    string        `json:"SignatureEmail,omitempty"`
	XAttr             string        `json:"XAttr,omitempty"`
	Blocks            []Block       `json:"Blocks,omitempty"`
}

// Block is a block of file content.
type Block struct {
	Index          int    `json:"Index"`
	BareURL        string `json:"BareURL"`
	Token          string `json:"Token"`
	Hash           string `json:"Hash"` // base64 SHA-256 of encrypted data
	EncSignature   string `json:"EncSignature"`
	SignatureEmail string `json:"SignatureEmail"`
}

// CreateFileReq is the body for POST /drive/v2/volumes/{volumeID}/files.
type CreateFileReq struct {
	CreateNodeReq
	MIMEType string `json:"MIMEType"`

	ContentKeyPacket          string `json:"ContentKeyPacket"`
	ContentKeyPacketSignature string `json:"ContentKeyPacketSignature"`

	// SignatureAddress overrides SignatureEmail for file creation (same field,
	// different JSON key required by the file endpoint).
	SignatureAddress string `json:"SignatureAddress"`
}

// CreateFileResp is the response from POST .../files.
type CreateFileResp struct {
	Response
	File struct {
		ID         string `json:"ID"`
		RevisionID string `json:"RevisionID"`
	} `json:"File"`
}

// CreateRevisionResp is the response from POST .../files/{linkID}/revisions.
type CreateRevisionResp struct {
	Response
	Revision struct {
		ID string `json:"ID"`
	} `json:"Revision"`
}

// GetRevisionResp is the response from GET .../files/{linkID}/revisions/{revisionID}.
type GetRevisionResp struct {
	Response
	Revision Revision `json:"Revision"`
}

// ListRevisionsResp is the response from GET .../files/{linkID}/revisions.
type ListRevisionsResp struct {
	Response
	Revisions []Revision `json:"Revisions"`
}

// VerificationResp is the response from GET .../links/{linkID}/revisions/{revisionID}/verification.
type VerificationResp struct {
	Response
	VerificationCode string `json:"VerificationCode"` // base64-encoded token
	ContentKeyPacket string `json:"ContentKeyPacket"`
}

// CommitRevisionReq is the body for PUT .../files/{linkID}/revisions/{revisionID}.
type CommitRevisionReq struct {
	ManifestSignature string        `json:"ManifestSignature"`
	SignatureAddress  string        `json:"SignatureAddress"`
	XAttr             string        `json:"XAttr"`
	State             RevisionState `json:"State"`
}

// ---- Block upload ----------------------------------------------------------

// BlockVerifier holds the verification token for a block upload.
type BlockVerifier struct {
	Token string `json:"Token"` // base64-encoded verification token
}

// BlockUploadInfo describes one block to be uploaded.
// Note: Size and Hash are intentionally omitted per the SDK spec.
type BlockUploadInfo struct {
	Index        int           `json:"Index"`
	EncSignature string        `json:"EncSignature"`
	Verifier     BlockVerifier `json:"Verifier"`
}

// BlockUploadReq is the body for POST /drive/blocks.
type BlockUploadReq struct {
	AddressID     string            `json:"AddressID"`
	VolumeID      string            `json:"VolumeID"`
	LinkID        string            `json:"LinkID"`
	RevisionID    string            `json:"RevisionID"`
	BlockList     []BlockUploadInfo `json:"BlockList"`
	ThumbnailList []interface{}     `json:"ThumbnailList,omitempty"`
}

// BlockUploadLink holds the signed URL and token for a block upload.
type BlockUploadLink struct {
	Index   int    `json:"Index"`
	Token   string `json:"Token"`
	BareURL string `json:"BareURL"`
}

// BlockUploadResp is the response from POST /drive/blocks.
type BlockUploadResp struct {
	Response
	UploadLinks []BlockUploadLink `json:"UploadLinks"`
}

// ---- Move / Rename ---------------------------------------------------------

// MoveLinkReq is the body for PUT .../links/{linkID}/move or .../rename.
type MoveLinkReq struct {
	// For rename only
	Name string `json:"Name,omitempty"`
	Hash string `json:"Hash,omitempty"`
	// For move
	ParentLinkID string `json:"ParentLinkID,omitempty"`
	OriginalHash string `json:"OriginalHash,omitempty"`

	NameSignatureEmail      string `json:"NameSignatureEmail,omitempty"`
	NodePassphrase          string `json:"NodePassphrase,omitempty"`
	NodePassphraseSignature string `json:"NodePassphraseSignature,omitempty"`
	SignatureEmail          string `json:"SignatureEmail,omitempty"`
	// ContentHash must be sent explicitly as null for file moves (not omitted).
	// Use a pointer so that nil serialises as JSON null rather than being omitted.
	ContentHash *string `json:"ContentHash"`
}

// ---- Trash -----------------------------------------------------------------

// TrashLinksReq is the body for POST .../trash_multiple.
type TrashLinksReq struct {
	LinkIDs []string `json:"LinkIDs"`
}

// TrashLinksResp is the response from POST .../trash_multiple.
type TrashLinksResp struct {
	Response
	Responses []struct {
		LinkID   string   `json:"LinkID"`
		Response Response `json:"Response"`
	} `json:"Responses"`
}

// ---- Hash availability -----------------------------------------------------

// CheckHashesReq is the body for POST .../checkAvailableHashes.
type CheckHashesReq struct {
	Hashes []string `json:"Hashes"`
}

// CheckHashesResp is the response from POST .../checkAvailableHashes.
type CheckHashesResp struct {
	Response
	AvailableHashes []string `json:"AvailableHashes"`
	PendingHashes   []string `json:"PendingHashes,omitempty"`
}

// ---- Events ----------------------------------------------------------------

// LatestEventResp is the response from GET .../events/latest.
type LatestEventResp struct {
	Response
	EventID string `json:"EventID"`
}

// EventLinkData is the link identity data embedded in a v2 drive event
// (EventLinkDataDto in the OpenAPI spec).
type EventLinkData struct {
	LinkID       string `json:"LinkID"`
	ParentLinkID string `json:"ParentLinkID,omitempty"`
	IsShared     bool   `json:"IsShared"`
	IsTrashed    bool   `json:"IsTrashed"`
}

// DriveEventLink is a single event from the v2 volume events endpoint
// (EventV2ResponseDto in the OpenAPI spec).
type DriveEventLink struct {
	EventID   string        `json:"EventID"`
	EventType EventAction   `json:"EventType"`
	Link      EventLinkData `json:"Link"`
}

// EventAction is the type of a drive event action (EventType in the v2 API).
type EventAction int

const (
	// EventActionDelete is a delete event (EventType=0).
	EventActionDelete EventAction = 0
	// EventActionCreate is a create event (EventType=1).
	EventActionCreate EventAction = 1
	// EventActionUpdate is an update event (EventType=2).
	EventActionUpdate EventAction = 2
	// EventActionUpdateMetadata is a metadata-only update event (EventType=3).
	EventActionUpdateMetadata EventAction = 3
)

// DriveEventResp is the response from GET .../events/{eventID}.
type DriveEventResp struct {
	Response
	EventID string           `json:"EventID"`
	More    bool             `json:"More"` // true if more events to fetch
	Events  []DriveEventLink `json:"Events,omitempty"`
}

// ---- XAttr (Extended attributes) ------------------------------------------

// RevisionXAttrCommon is the plaintext content of a revision's XAttr.
type RevisionXAttrCommon struct {
	ModificationTime string            `json:"ModificationTime"` // ISO 8601
	Size             int64             `json:"Size"`
	BlockSizes       []int64           `json:"BlockSizes"`
	Digests          map[string]string `json:"Digests"` // e.g. {"SHA1": "..."}
}

// RevisionXAttr is the top-level XAttr JSON structure (wraps Common).
type RevisionXAttr struct {
	Common RevisionXAttrCommon `json:"Common"`
}

// ---- Batched links request -------------------------------------------------

// BatchLinksReq is the body for POST /drive/v2/volumes/{volumeID}/links.
type BatchLinksReq struct {
	LinkIDs []string `json:"LinkIDs"`
}

// ---- Standard share (per-node) creation ------------------------------------

// CreateStandardShareReq is the body for POST /drive/volumes/{volumeID}/shares.
// This creates a new non-main share rooted at a specific link (for sharing a
// file or folder via a public link).
type CreateStandardShareReq struct {
	AddressID                string `json:"AddressID"`
	RootLinkID               string `json:"RootLinkID"`
	Name                     string `json:"Name"`
	ShareKey                 string `json:"ShareKey"`                 // armored public key of new share
	SharePassphrase          string `json:"SharePassphrase"`          // armored PGP message (passphrase encrypted to addrKR)
	SharePassphraseSignature string `json:"SharePassphraseSignature"` // armored detached signature
	PassphraseKeyPacket      string `json:"PassphraseKeyPacket"`      // session key encrypted to node key
	NameKeyPacket            string `json:"NameKeyPacket"`            // name session key re-encrypted to the new share key (base64)
}

// CreateStandardShareResp is the response from POST /drive/volumes/{volumeID}/shares.
type CreateStandardShareResp struct {
	Response
	Share struct {
		ID              string `json:"ID"`
		EditorsCanShare bool   `json:"EditorsCanShare"`
	} `json:"Share"`
}

// VolumeShareLink is a single entry in the ListVolumeSharesResp Links array.
// Returned by GET /drive/v2/volumes/{volumeID}/shares.
type VolumeShareLink struct {
	ShareID        string `json:"ShareID"`
	LinkID         string `json:"LinkID"`
	ContextShareID string `json:"ContextShareID"`
}

// ListVolumeSharesResp is the response from GET /drive/v2/volumes/{volumeID}/shares.
type ListVolumeSharesResp struct {
	Response
	Links    []VolumeShareLink `json:"Links"`
	AnchorID string            `json:"AnchorID,omitempty"`
	More     bool              `json:"More"`
}

// ---- Share URL (public link) -----------------------------------------------

// CreateShareURLReq is the body for POST /drive/shares/{shareID}/urls.
type CreateShareURLReq struct {
	CreatorEmail             string `json:"CreatorEmail"`
	Permissions              int    `json:"Permissions"`
	UrlPasswordSalt          string `json:"UrlPasswordSalt"`          // base64, random 16 bytes (SRP salt)
	SharePasswordSalt        string `json:"SharePasswordSalt"`        // base64, random 16 bytes (bcrypt salt)
	SRPVerifier              string `json:"SRPVerifier"`              // base64 SRP verifier
	SRPModulusID             string `json:"SRPModulusID"`             // ID from GET /auth/v4/modulus
	Flags                    int    `json:"Flags"`                    // 2 = random password
	SharePassphraseKeyPacket string `json:"SharePassphraseKeyPacket"` // base64, session key wrapped with bcrypt passphrase
	Password                 string `json:"Password"`                 // PGP-armored password encrypted to address key
	MaxAccesses              int    `json:"MaxAccesses"`              // 0 = unlimited
	ExpirationDuration       *int64 `json:"ExpirationDuration"`       // seconds, null = no expiry
}

// ShareURLData is the shape of a ShareURL object in API responses.
type ShareURLData struct {
	ShareURLID               string `json:"ShareURLID"`
	ShareID                  string `json:"ShareID"`
	Token                    string `json:"Token"`
	PublicURL                string `json:"PublicUrl"`
	CreatorEmail             string `json:"CreatorEmail"`
	Permissions              int    `json:"Permissions"`
	Flags                    int    `json:"Flags"`
	UrlPasswordSalt          string `json:"UrlPasswordSalt"`
	SharePasswordSalt        string `json:"SharePasswordSalt"`
	SRPVerifier              string `json:"SRPVerifier"`
	SRPModulusID             string `json:"SRPModulusID"`
	Password                 string `json:"Password"`
	SharePassphraseKeyPacket string `json:"SharePassphraseKeyPacket"`
	ExpirationTime           *int64 `json:"ExpirationTime,omitempty"`
}

// CreateShareURLResp is the response from POST /drive/shares/{shareID}/urls.
type CreateShareURLResp struct {
	Response
	ShareURL ShareURLData `json:"ShareURL"`
}

// ListShareURLsResp is the response from GET /drive/shares/{shareID}/urls.
type ListShareURLsResp struct {
	Response
	ShareURLs []ShareURLData `json:"ShareURLs"`
}

// DeleteShareURLsReq is the body for POST /drive/shares/{shareID}/urls/delete_multiple.
type DeleteShareURLsReq struct {
	ShareURLIDs []string `json:"ShareURLIDs"`
}
