//go:build linux

package nativeprofile

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestNamedPipeSkipped(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "conan.lock"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 0 || len(f.Warnings) != 1 || !strings.Contains(f.Warnings[0], "non-regular file skipped") {
		t.Fatalf("FIFO was not skipped: %+v", f)
	}
}
