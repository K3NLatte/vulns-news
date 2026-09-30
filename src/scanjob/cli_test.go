package scanjob

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCLIBridge(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "scanner")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	buildCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	if out, err := exec.CommandContext(buildCtx, "go", "build", "-o", binary, "./testdata/scanner.go").CombinedOutput(); err != nil {
		t.Fatalf("fixture build: %v %s", err, out)
	}
	cli, err := NewCLI(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "failure", "invalid", "oversized", "incomplete", "timeout", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "marker")
			t.Setenv("SCANJOB_MARKER", marker)
			timeout := 3 * time.Second
			if mode == "timeout" {
				timeout = 150 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			req := valid
			req.Ref = mode
			if mode == "cancel" {
				req.Ref = "timeout"
				go func() { time.Sleep(150 * time.Millisecond); cancel() }()
			}
			summary, err := cli.Scan(ctx, req)
			if mode == "success" {
				if err != nil || summary.CommitSHA != "abc" || !summary.RefreshComplete {
					t.Fatal(summary, err)
				}
			} else if err == nil || strings.Contains(err.Error(), "private stderr") {
				t.Fatal(err)
			}
			dir, readErr := os.ReadFile(marker)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, err := os.Stat(string(dir)); !os.IsNotExist(err) {
				t.Fatalf("temporary files remain: %s: %v", dir, err)
			}
		})
	}
	if _, err := cli.Scan(context.Background(), valid); err == nil {
		t.Fatal("unbounded context accepted")
	}
}
func TestCLIValidationAndCapture(t *testing.T) {
	for _, path := range []string{"", t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if _, err := NewCLI(path); err == nil {
			t.Fatal("accepted", path)
		}
	}
	if runtime.GOOS != "windows" {
		p := filepath.Join(t.TempDir(), "file")
		_ = os.WriteFile(p, []byte("no"), 0600)
		if _, err := NewCLI(p); err == nil {
			t.Fatal("nonexecutable accepted")
		}
	}
	b := &boundedBuffer{limit: 10}
	if n, err := b.Write([]byte(strings.Repeat("x", 100))); n != 100 || err != nil || b.Len() != 10 || !b.overflow {
		t.Fatal(b, n, err)
	}
	if n, err := b.Write([]byte("more")); n != 4 || err != nil || b.Len() != 10 {
		t.Fatal(b, n, err)
	}
}
