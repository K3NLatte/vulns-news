//go:build linux

package scanjob

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestCancellationKillsDescendants(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "scanner")
	buildCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	if out, err := exec.CommandContext(buildCtx, "go", "build", "-o", binary, "./testdata/scanner.go").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	heartbeat := filepath.Join(t.TempDir(), "heartbeat")
	t.Setenv("SCANJOB_HEARTBEAT", heartbeat)
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("SCANJOB_MARKER", marker)
	cli, err := NewCLI(binary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { r := valid; r.Ref = "descendant"; _, err := cli.Scan(ctx, r); done <- err }()
	until := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(heartbeat); err == nil {
			break
		}
		if time.Now().After(until) {
			t.Fatal("child did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled scan succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not stop")
	}
	first, err := os.ReadFile(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	second, err := os.ReadFile(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("descendant survived cancellation")
	}
	dir, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(dir)); !os.IsNotExist(err) {
		t.Fatal("workspace survived", err)
	}
}
