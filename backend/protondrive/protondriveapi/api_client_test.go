package protondriveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestClient creates a ProtonClient pointed at the given httptest.Server.
func newTestClient(t *testing.T, srv *httptest.Server) *ProtonClient {
	t.Helper()
	c, err := NewProtonClient(http.DefaultClient, srv.URL, "")
	require.NoError(t, err)
	// Inject fake credentials so authenticated calls don't bail out early.
	c.SetTokens("test-uid", "test-access-token", "")
	return c
}

// respondJSON writes a JSON response with the given HTTP status code.
func respondJSON(w http.ResponseWriter, httpStatus int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(payload)
}

// filesShareJSON returns a minimal valid JSON body for the my-files endpoint.
func filesShareJSON() map[string]interface{} {
	return map[string]interface{}{
		"Code":   1000,
		"Volume": map[string]interface{}{"VolumeID": "v1"},
		"Share":  map[string]interface{}{"ShareID": "s1"},
		"Link":   map[string]interface{}{"Link": map[string]interface{}{"LinkID": "l1"}},
	}
}

// ---- Header checks ---------------------------------------------------------

func TestProtonClientSetsAppVersionHeader(t *testing.T) {
	var gotAppVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAppVersion = r.Header.Get("x-pm-appversion")
		respondJSON(w, http.StatusOK, filesShareJSON())
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	_, err := c.GetFilesShare(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, gotAppVersion, "x-pm-appversion header must be set")
	assert.Contains(t, gotAppVersion, "@", "x-pm-appversion must contain '@' separator")
}

func TestProtonClientSetsAuthorizationHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		respondJSON(w, http.StatusOK, filesShareJSON())
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	_, err := c.GetFilesShare(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "Bearer test-access-token", gotAuth)
}

// ---- GetFilesShare ---------------------------------------------------------

func TestGetFilesShare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/drive/v2/shares/my-files", r.URL.Path)
		respondJSON(w, http.StatusOK, FilesShareResp{
			Response: Response{Code: CodeSuccess},
			Volume:   FilesShareVolume{VolumeID: "vol1"},
			Share:    Share{ShareID: "share1"},
			Link:     FilesShareLink{Link: FilesShareLinkCore{LinkID: "root1"}},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	share, err := c.GetFilesShare(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "share1", share.Share.ShareID)
	assert.Equal(t, "vol1", share.Volume.VolumeID)
	assert.Equal(t, "root1", share.Link.Link.LinkID)
}

// ---- BatchGetLinks ---------------------------------------------------------

func TestBatchGetLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/links", r.URL.Path)

		var req BatchLinksReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, []string{"l1", "l2"}, req.LinkIDs)

		respondJSON(w, http.StatusOK, LinksResp{
			Response: Response{Code: CodeSuccess},
			Links: []LinkWrapper{
				{Link: LinkCore{LinkID: "l1", Type: LinkTypeFolder}},
				{Link: LinkCore{LinkID: "l2", Type: LinkTypeFile}},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	links, err := c.BatchGetLinks(context.Background(), "v1", []string{"l1", "l2"})
	require.NoError(t, err)
	require.Len(t, links, 2)
	assert.Equal(t, "l1", links[0].Link.LinkID)
	assert.Equal(t, "l2", links[1].Link.LinkID)
}

// ---- ListFolderChildren ----------------------------------------------------

func TestListFolderChildren(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/drive/v2/volumes/v1/folders/root1/children":
			respondJSON(w, http.StatusOK, FolderChildrenResp{
				Response: Response{Code: CodeSuccess},
				LinkIDs:  []string{"child1"},
				More:     false,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/drive/v2/volumes/v1/links":
			respondJSON(w, http.StatusOK, LinksResp{
				Response: Response{Code: CodeSuccess},
				Links: []LinkWrapper{
					{Link: LinkCore{LinkID: "child1", Type: LinkTypeFile}},
				},
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	children, err := c.ListFolderChildren(context.Background(), "v1", "root1")
	require.NoError(t, err)
	require.Len(t, children, 1)
	assert.Equal(t, "child1", children[0].Link.LinkID)
}

func TestListFolderChildrenPaginated(t *testing.T) {
	childrenCallCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/drive/v2/volumes/v1/folders/root1/children":
			childrenCallCount++
			switch childrenCallCount {
			case 1:
				assert.Empty(t, r.URL.Query().Get("AnchorID"))
				respondJSON(w, http.StatusOK, FolderChildrenResp{
					Response: Response{Code: CodeSuccess},
					LinkIDs:  []string{"child1"},
					AnchorID: "anchor1",
					More:     true,
				})
			case 2:
				assert.Equal(t, "anchor1", r.URL.Query().Get("AnchorID"))
				respondJSON(w, http.StatusOK, FolderChildrenResp{
					Response: Response{Code: CodeSuccess},
					LinkIDs:  []string{"child2"},
					More:     false,
				})
			default:
				t.Errorf("unexpected children call %d", childrenCallCount)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/drive/v2/volumes/v1/links":
			var req BatchLinksReq
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			var wrappers []LinkWrapper
			for _, id := range req.LinkIDs {
				wrappers = append(wrappers, LinkWrapper{Link: LinkCore{LinkID: id}})
			}
			respondJSON(w, http.StatusOK, LinksResp{
				Response: Response{Code: CodeSuccess},
				Links:    wrappers,
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	children, err := c.ListFolderChildren(context.Background(), "v1", "root1")
	require.NoError(t, err)
	require.Len(t, children, 2)
	assert.Equal(t, "child1", children[0].Link.LinkID)
	assert.Equal(t, "child2", children[1].Link.LinkID)
}

// TestWalkFolderChildrenEarlyExit verifies that returning a non-nil error from
// the callback stops the walk immediately and that error is propagated unwrapped.
func TestWalkFolderChildrenEarlyExit(t *testing.T) {
	batchCalls := 0
	sentinel := errors.New("stop")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/drive/v2/volumes/v1/folders/root1/children":
			respondJSON(w, http.StatusOK, FolderChildrenResp{
				Response: Response{Code: CodeSuccess},
				// Three pages each with 100 IDs so there would be 3 BatchGetLinks calls.
				// We expect the walk to stop after the first batch.
				LinkIDs:  makeIDSlice("child", 100),
				AnchorID: "anchor1",
				More:     true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/drive/v2/volumes/v1/links":
			batchCalls++
			var req BatchLinksReq
			require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
			var wrappers []LinkWrapper
			for _, id := range req.LinkIDs {
				wrappers = append(wrappers, LinkWrapper{Link: LinkCore{LinkID: id}})
			}
			respondJSON(w, http.StatusOK, LinksResp{
				Response: Response{Code: CodeSuccess},
				Links:    wrappers,
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.WalkFolderChildren(context.Background(), "v1", "root1", func(_ []LinkWrapper) error {
		return sentinel // stop immediately
	})
	require.ErrorIs(t, err, sentinel, "sentinel error must be propagated unwrapped")
	assert.Equal(t, 1, batchCalls, "walk must stop after first batch")
}

// makeIDSlice returns n IDs of the form "<prefix>0", "<prefix>1", …
func makeIDSlice(prefix string, n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return ids
}

// ---- CreateFolder ----------------------------------------------------------

func TestCreateFolder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/folders", r.URL.Path)

		var req CreateFolderReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "parent1", req.ParentLinkID)
		assert.Equal(t, "enc-name", req.Name)

		respondJSON(w, http.StatusOK, CreateFolderResp{
			Response: Response{Code: CodeSuccess},
			Folder: struct {
				ID string `json:"ID"`
			}{ID: "new-folder-1"},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	folderID, err := c.CreateFolder(context.Background(), "v1", &CreateFolderReq{
		CreateNodeReq: CreateNodeReq{
			ParentLinkID: "parent1",
			Name:         "enc-name",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "new-folder-1", folderID)
}

// ---- CreateFile ------------------------------------------------------------

func TestCreateFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/files", r.URL.Path)

		respondJSON(w, http.StatusOK, CreateFileResp{
			Response: Response{Code: CodeSuccess},
			File: struct {
				ID         string `json:"ID"`
				RevisionID string `json:"RevisionID"`
			}{ID: "file1", RevisionID: "rev1"},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	fileID, revID, err := c.CreateFile(context.Background(), "v1", &CreateFileReq{
		CreateNodeReq: CreateNodeReq{
			ParentLinkID: "parent1",
			Name:         "enc-name",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "file1", fileID)
	assert.Equal(t, "rev1", revID)
}

// ---- CreateRevision --------------------------------------------------------

func TestCreateRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/files/file1/revisions", r.URL.Path)

		respondJSON(w, http.StatusOK, CreateRevisionResp{
			Response: Response{Code: CodeSuccess},
			Revision: struct {
				ID string `json:"ID"`
			}{ID: "rev2"},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	revID, err := c.CreateRevision(context.Background(), "v1", "file1")
	require.NoError(t, err)
	assert.Equal(t, "rev2", revID)
}

// ---- GetRevision -----------------------------------------------------------

func TestGetRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/files/file1/revisions/rev1", r.URL.Path)

		respondJSON(w, http.StatusOK, GetRevisionResp{
			Response: Response{Code: CodeSuccess},
			Revision: Revision{
				ID:    "rev1",
				State: RevisionStateActive,
				Blocks: []Block{
					{Index: 1, BareURL: "https://storage.example.com/block1", Token: "tok1"},
				},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	rev, err := c.GetRevision(context.Background(), "v1", "file1", "rev1")
	require.NoError(t, err)
	assert.Equal(t, "rev1", rev.ID)
	require.Len(t, rev.Blocks, 1)
	assert.Equal(t, "tok1", rev.Blocks[0].Token)
}

// ---- CommitRevision --------------------------------------------------------

func TestCommitRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/files/file1/revisions/rev1", r.URL.Path)

		var req CommitRevisionReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, RevisionStateActive, req.State)

		respondJSON(w, http.StatusOK, Response{Code: CodeSuccess})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.CommitRevision(context.Background(), "v1", "file1", "rev1", &CommitRevisionReq{State: RevisionStateActive})
	require.NoError(t, err)
}

// ---- DeleteRevision --------------------------------------------------------

func TestDeleteRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/files/file1/revisions/rev1", r.URL.Path)
		respondJSON(w, http.StatusOK, Response{Code: CodeSuccess})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.DeleteRevision(context.Background(), "v1", "file1", "rev1")
	require.NoError(t, err)
}

// ---- RequestBlockUploadURLs ------------------------------------------------

func TestRequestBlockUploadURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/drive/blocks", r.URL.Path)

		var req BlockUploadReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "v1", req.VolumeID)
		assert.Len(t, req.BlockList, 1)

		respondJSON(w, http.StatusOK, BlockUploadResp{
			Response: Response{Code: CodeSuccess},
			UploadLinks: []BlockUploadLink{
				{Index: 1, BareURL: "https://storage.example.com/upload/b1", Token: "tok-upload"},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	links, err := c.RequestBlockUploadURLs(context.Background(), &BlockUploadReq{
		VolumeID: "v1",
		BlockList: []BlockUploadInfo{
			{Index: 1},
		},
	})
	require.NoError(t, err)
	require.Len(t, links, 1)
	assert.Equal(t, "tok-upload", links[0].Token)
}

// ---- RenameLink ------------------------------------------------------------

func TestRenameLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/links/link1/rename", r.URL.Path)

		var req MoveLinkReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "new-enc-name", req.Name)

		respondJSON(w, http.StatusOK, Response{Code: CodeSuccess})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.RenameLink(context.Background(), "v1", "link1", &MoveLinkReq{Name: "new-enc-name"})
	require.NoError(t, err)
}

// ---- MoveLink --------------------------------------------------------------

func TestMoveLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/links/link1/move", r.URL.Path)

		var req MoveLinkReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "newparent1", req.ParentLinkID)

		respondJSON(w, http.StatusOK, Response{Code: CodeSuccess})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.MoveLink(context.Background(), "v1", "link1", &MoveLinkReq{ParentLinkID: "newparent1"})
	require.NoError(t, err)
}

// ---- TrashLinks ------------------------------------------------------------

func TestTrashLinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/trash_multiple", r.URL.Path)

		var req TrashLinksReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Len(t, req.LinkIDs, 1)
		assert.Equal(t, "link1", req.LinkIDs[0])

		respondJSON(w, http.StatusOK, TrashLinksResp{
			Response: Response{Code: CodeSuccess},
			Responses: []struct {
				LinkID   string   `json:"LinkID"`
				Response Response `json:"Response"`
			}{
				{LinkID: "link1", Response: Response{Code: 1000}},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.TrashLinks(context.Background(), "v1", []string{"link1"})
	require.NoError(t, err)
}

func TestTrashLinksPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, TrashLinksResp{
			Response: Response{Code: CodeSuccess},
			Responses: []struct {
				LinkID   string   `json:"LinkID"`
				Response Response `json:"Response"`
			}{
				{LinkID: "link1", Response: Response{Code: 1000}},
				{LinkID: "link2", Response: Response{Code: CodeMaybeOutdated}},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.TrashLinks(context.Background(), "v1", []string{"link1", "link2"})
	require.ErrorContains(t, err, "link2")
	require.ErrorContains(t, err, "2000")
}

// ---- EmptyTrash ------------------------------------------------------------

func TestEmptyTrash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/drive/volumes/v1/trash", r.URL.Path)
		respondJSON(w, http.StatusOK, Response{Code: CodeSuccess})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	err := c.EmptyTrash(context.Background(), "v1")
	require.NoError(t, err)
}

// ---- CheckAvailableHashes --------------------------------------------------

func TestCheckAvailableHashes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/links/folder1/checkAvailableHashes", r.URL.Path)

		var req CheckHashesReq
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, []string{"hash1", "hash2"}, req.Hashes)

		respondJSON(w, http.StatusOK, CheckHashesResp{
			Response:        Response{Code: 1000},
			AvailableHashes: []string{"hash1"},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	resp, err := c.CheckAvailableHashes(context.Background(), "v1", "folder1", []string{"hash1", "hash2"})
	require.NoError(t, err)
	assert.Equal(t, []string{"hash1"}, resp.AvailableHashes)
}

// ---- GetLatestEventID ------------------------------------------------------

func TestGetLatestEventID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/drive/volumes/v1/events/latest", r.URL.Path)
		respondJSON(w, http.StatusOK, LatestEventResp{
			Response: Response{Code: CodeSuccess},
			EventID:  "event-abc",
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	eventID, err := c.GetLatestEventID(context.Background(), "v1")
	require.NoError(t, err)
	assert.Equal(t, "event-abc", eventID)
}

// ---- PollEvents ------------------------------------------------------------

func TestPollEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/drive/v2/volumes/v1/events/event-abc", r.URL.Path)
		respondJSON(w, http.StatusOK, DriveEventResp{
			Response: Response{Code: CodeSuccess},
			EventID:  "event-def",
			More:     false,
			Events: []DriveEventLink{
				{EventID: "ev1", EventType: EventActionCreate, Link: EventLinkData{LinkID: "link1"}},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	resp, err := c.PollEvents(context.Background(), "v1", "event-abc")
	require.NoError(t, err)
	assert.Equal(t, "event-def", resp.EventID)
	require.Len(t, resp.Events, 1)
	assert.Equal(t, "link1", resp.Events[0].Link.LinkID)
}

// ---- token refresh (401 → refresh → retry) ---------------------------------

func TestTokenRefreshOn401(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/v4/refresh":
			respondJSON(w, http.StatusOK, AuthRefreshResp{
				Response:     Response{Code: 1000},
				UID:          "test-uid",
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
			})
		case "/drive/v2/shares/my-files":
			callCount++
			if callCount == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(Error{Code: 401, Message: "Unauthorized"})
				return
			}
			respondJSON(w, http.StatusOK, FilesShareResp{
				Response: Response{Code: CodeSuccess},
				Volume:   FilesShareVolume{VolumeID: "v1"},
				Share:    Share{ShareID: "s1"},
				Link:     FilesShareLink{Link: FilesShareLinkCore{LinkID: "l1"}},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	c.SetTokens(c.UID(), c.AccessToken(), "old-refresh-token")

	share, err := c.GetFilesShare(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "s1", share.Share.ShareID)
	assert.Equal(t, 2, callCount, "original call + retry after refresh = 2")
	assert.Equal(t, "new-access-token", c.AccessToken())
}

// TestConcurrentTokenRefresh verifies that when multiple goroutines receive a
// 401 simultaneously, the refresh endpoint is called exactly once.
func TestConcurrentTokenRefresh(t *testing.T) {
	var refreshCount int
	var refreshMu sync.Mutex

	// Each goroutine gets its own call counter so we can assert total calls.
	var totalAPICallsMu sync.Mutex
	totalAPICalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/v4/refresh":
			refreshMu.Lock()
			refreshCount++
			refreshMu.Unlock()
			respondJSON(w, http.StatusOK, AuthRefreshResp{
				Response:     Response{Code: 1000},
				UID:          "test-uid",
				AccessToken:  "refreshed-token",
				RefreshToken: "new-refresh-token",
			})
		case "/drive/v2/shares/my-files":
			totalAPICallsMu.Lock()
			n := totalAPICalls
			totalAPICalls++
			totalAPICallsMu.Unlock()
			// All initial calls (one per goroutine) return 401.
			// Retries (after refresh) succeed.
			if r.Header.Get("Authorization") != "Bearer refreshed-token" && n < 5 {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(Error{Code: 401, Message: "Unauthorized"})
				return
			}
			respondJSON(w, http.StatusOK, FilesShareResp{
				Response: Response{Code: CodeSuccess},
				Volume:   FilesShareVolume{VolumeID: "v1"},
				Share:    Share{ShareID: "s1"},
				Link:     FilesShareLink{Link: FilesShareLinkCore{LinkID: "l1"}},
			})
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	c.SetTokens(c.UID(), "stale-token", "old-refresh-token")

	const goroutines = 5
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = c.GetFilesShare(context.Background())
		}()
	}
	wg.Wait()

	refreshMu.Lock()
	got := refreshCount
	refreshMu.Unlock()
	assert.Equal(t, 1, got, "refresh endpoint must be called exactly once regardless of concurrent 401s")
}

// ---- error decoding --------------------------------------------------------

func TestAPIErrorDecoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusUnprocessableEntity, Error{Code: CodeStaleRevision, Message: "already exists"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv)
	c.SetTokens(c.UID(), c.AccessToken(), "") // no refresh token
	_, err := c.GetFilesShare(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}
