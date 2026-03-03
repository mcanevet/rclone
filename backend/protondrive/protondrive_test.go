package protondrive_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/rclone/rclone/backend/protondrive"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/list"
	"github.com/rclone/rclone/fs/operations"
	"github.com/rclone/rclone/fstest"
	"github.com/rclone/rclone/fstest/fstests"
)

const testRemote = "TestProtonDrive:"

// TestMain purges leftover rclone-test-* directories from prior runs before
// executing the test suite.  This avoids accumulation of stale test data in
// the account while keeping tests hermetic (each run still creates its own
// randomly-named subdirectory via fstest.RandomRemoteName).
func TestMain(m *testing.M) {
	fstest.Initialise()
	purgeOldTestDirs()
	os.Exit(m.Run())
}

// purgeOldTestDirs lists the root of testRemote and removes every directory
// whose name matches the fstest.MatchTestRemote pattern.  Errors are logged
// but do not abort the run — the test suite should still execute even when
// cleanup is partially unavailable.
func purgeOldTestDirs() {
	ctx := context.Background()
	root, err := fs.NewFs(ctx, testRemote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protondrive_test: purgeOldTestDirs: NewFs(%q): %v\n", testRemote, err)
		return
	}
	entries, err := list.DirSorted(ctx, root, true, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "protondrive_test: purgeOldTestDirs: list: %v\n", err)
		return
	}
	for _, e := range entries {
		dir, ok := e.(fs.Directory)
		if !ok {
			continue
		}
		name := dir.Remote()
		if !fstest.MatchTestRemote.MatchString(name) {
			continue
		}
		fullPath := testRemote + name
		subFs, err := fs.NewFs(ctx, fullPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "protondrive_test: purgeOldTestDirs: NewFs(%q): %v\n", fullPath, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "protondrive_test: purging old test dir %q\n", fullPath)
		if err := operations.Purge(ctx, subFs, ""); err != nil {
			fmt.Fprintf(os.Stderr, "protondrive_test: purgeOldTestDirs: Purge(%q): %v\n", fullPath, err)
		}
	}
}

// TestIntegration runs integration tests against the remote
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: testRemote,
		NilObject:  (*protondrive.Object)(nil),
	})
}
