//go:build linux

package loader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanPinDir_RemovesFilesLeavesDirs(t *testing.T) {
	dir := t.TempDir()

	// Simulate pinned objects as plain files.
	if err := os.WriteFile(filepath.Join(dir, "egress_map"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// Simulate unexpected subdir; we should not recurse.
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	if err := cleanPinDir(dir); err != nil {
		t.Fatalf("cleanPinDir: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "egress_map")); err == nil {
		t.Fatalf("expected file to be removed")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat file: %v", err)
	}

	if fi, err := os.Stat(filepath.Join(dir, "subdir")); err != nil {
		t.Fatalf("stat subdir: %v", err)
	} else if !fi.IsDir() {
		t.Fatalf("expected subdir to remain a directory")
	}
}

