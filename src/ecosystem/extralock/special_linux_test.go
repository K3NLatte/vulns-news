//go:build linux

package extralock

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSpecialFileSkipped(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "deno.lock"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Profile(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Components) != 0 || len(f.Warnings) != 1 || !strings.Contains(f.Warnings[0], "special file skipped") {
		t.Fatalf("unexpected FIFO inventory: %+v", f)
	}
}
