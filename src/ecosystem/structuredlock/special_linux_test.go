//go:build linux

package structuredlock

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestSpecialFile(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "Cargo.lock"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Components) != 0 || len(got.Warnings) != 1 {
		t.Fatalf("%+v", got)
	}
}
