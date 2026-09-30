package scanjob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// CLI invokes a trusted, prebuilt repo-scan executable, never a shell.
type CLI struct{ binary string }

func NewCLI(binary string) (*CLI, error) {
	if binary == "" {
		return nil, errors.New("scanner binary path is required")
	}
	absolute, err := filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0) {
		return nil, errors.New("scanner must be a regular executable file")
	}
	return &CLI{binary: absolute}, nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

func (c *CLI) Scan(ctx context.Context, r Request) (Summary, error) {
	var summary Summary
	r, err := Validate(r)
	if err != nil {
		return summary, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return summary, errors.New("scanner requires a deadline")
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	dir, err := os.MkdirTemp("", "scanjob-")
	if err != nil {
		return summary, err
	}
	defer os.RemoveAll(dir)
	args := []string{"-repository", r.URL, "-state", filepath.Join(dir, "state.json"), "-nvd=false", "-timeout", time.Until(deadline).String()}
	if r.Ref != "" {
		args = append(args, "-ref", r.Ref)
	}
	cmd := exec.CommandContext(ctx, c.binary, args...)
	cmd.Env = append(os.Environ(), "TMPDIR="+dir, "TMP="+dir, "TEMP="+dir)
	cmd.WaitDelay = time.Second
	cleanup := configureProcess(cmd)
	defer cleanup()
	stdout := &boundedBuffer{limit: 4 << 20}
	stderr := &boundedBuffer{limit: 16 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
		return summary, errors.New("scanner process failed")
	}
	if stdout.overflow {
		return summary, errors.New("scanner output exceeded limit")
	}
	var out struct {
		Repository struct {
			CommitSHA string `json:"commit_sha"`
		} `json:"repository"`
		Report *struct {
			RefreshComplete bool `json:"refresh_complete"`
		} `json:"report"`
		Error string `json:"error"`
	}
	decoder := json.NewDecoder(&stdout.Buffer)
	if err := decoder.Decode(&out); err != nil {
		return summary, errors.New("invalid scanner output")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || out.Error != "" || out.Report == nil || out.Repository.CommitSHA == "" || !out.Report.RefreshComplete {
		return summary, errors.New("incomplete scanner result")
	}
	return Summary{CommitSHA: out.Repository.CommitSHA, RefreshComplete: out.Report.RefreshComplete}, nil
}
