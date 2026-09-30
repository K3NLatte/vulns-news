// Package repository safely acquires public GitHub repositories for static analysis.
// Acquisition checks out data only; it never intentionally executes repository code.
package repository

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"vulns-news/src/domain"
)

const (
	defaultCloneTimeout          = 2 * time.Minute
	defaultResolveTimeout        = 15 * time.Second
	defaultMaxCommandOutputBytes = int64(64 << 10)
)

var (
	ownerPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	commitSHAPattern  = regexp.MustCompile(`^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)
)

// RepositorySpec identifies the GitHub repository and optional branch or tag to
// acquire. An empty Ref means the repository's default branch at acquisition time.
type RepositorySpec struct {
	URL string
	Ref string
}

// AcquiredRepository is an immutable repository revision checked out under Path.
// The caller owns Path and must call Cleanup when it is no longer needed.
type AcquiredRepository struct {
	Identity domain.RepositoryIdentity
	Path     string

	cleanupPath string
}

// Cleanup recursively removes the acquired checkout. It is safe to call more than once.
func (r *AcquiredRepository) Cleanup() error {
	if r == nil || r.cleanupPath == "" {
		return nil
	}
	return os.RemoveAll(r.cleanupPath)
}

// Command describes one external command. Env is the complete environment, not
// additions to the parent process environment.
type Command struct {
	Name string
	Args []string
	Dir  string
	Env  []string
}

// CommandRunner permits command execution to be replaced in tests. Implementations
// must honor context cancellation to preserve configured timeouts.
type CommandRunner interface {
	Run(ctx context.Context, command Command) ([]byte, error)
}

// Config controls acquisition. Timeouts and MaxCommandOutputBytes are enforced by
// the default runner. A custom Runner is responsible for bounding its own output.
// No disk-space or file-count quota is enforced.
type Config struct {
	GitBinary             string
	CloneTimeout          time.Duration
	ResolveTimeout        time.Duration
	MaxCommandOutputBytes int64
	Runner                CommandRunner
}

// Acquirer clones repositories and resolves their checked-out commit.
type Acquirer struct {
	gitBinary      string
	cloneTimeout   time.Duration
	resolveTimeout time.Duration
	runner         CommandRunner
}

// NewAcquirer creates a repository acquirer with secure, non-interactive defaults.
func NewAcquirer(config Config) (*Acquirer, error) {
	if config.CloneTimeout < 0 {
		return nil, errors.New("clone timeout must not be negative")
	}
	if config.ResolveTimeout < 0 {
		return nil, errors.New("resolve timeout must not be negative")
	}
	if config.MaxCommandOutputBytes < 0 {
		return nil, errors.New("maximum command output must not be negative")
	}

	gitBinary := strings.TrimSpace(config.GitBinary)
	if gitBinary == "" {
		gitBinary = "git"
	}
	cloneTimeout := config.CloneTimeout
	if cloneTimeout == 0 {
		cloneTimeout = defaultCloneTimeout
	}
	resolveTimeout := config.ResolveTimeout
	if resolveTimeout == 0 {
		resolveTimeout = defaultResolveTimeout
	}
	outputLimit := config.MaxCommandOutputBytes
	if outputLimit == 0 {
		outputLimit = defaultMaxCommandOutputBytes
	}

	runner := config.Runner
	if runner == nil {
		runner = execRunner{maxOutputBytes: outputLimit}
	}

	return &Acquirer{
		gitBinary:      gitBinary,
		cloneTimeout:   cloneTimeout,
		resolveTimeout: resolveTimeout,
		runner:         runner,
	}, nil
}

// CanonicalizeGitHubURL validates a public-style GitHub HTTPS repository URL and
// returns https://github.com/owner/repository without a trailing .git or slash.
// Repository visibility is established later by an anonymous clone, not by URL syntax.
func CanonicalizeGitHubURL(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return "", errors.New("repository URL must be non-empty and contain no surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse repository URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return "", errors.New("repository URL must use HTTPS")
	}
	if !strings.EqualFold(parsed.Hostname(), "github.com") || parsed.Port() != "" {
		return "", errors.New("repository URL host must be github.com without a port")
	}
	if parsed.User != nil {
		return "", errors.New("repository URL must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("repository URL must not contain a query or fragment")
	}
	if parsed.RawPath != "" || strings.Contains(parsed.Path, "%") {
		return "", errors.New("repository URL path must not use percent encoding")
	}

	path := strings.TrimSuffix(parsed.Path, "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("repository URL path must be exactly owner/repository")
	}
	owner, name := parts[0], parts[1]
	if strings.HasSuffix(name, ".git") {
		name = strings.TrimSuffix(name, ".git")
	}
	if !ownerPattern.MatchString(owner) || strings.Contains(owner, "--") {
		return "", errors.New("repository owner is invalid")
	}
	if !repositoryPattern.MatchString(name) || name == "." || name == ".." {
		return "", errors.New("repository name is invalid")
	}

	return "https://github.com/" + owner + "/" + name, nil
}

// Acquire shallow-clones spec into a new directory inside workspace and resolves
// HEAD to a full commit SHA. On success the caller must call result.Cleanup().
func (a *Acquirer) Acquire(ctx context.Context, workspace string, spec RepositorySpec) (*AcquiredRepository, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	canonicalURL, err := CanonicalizeGitHubURL(spec.URL)
	if err != nil {
		return nil, err
	}
	if err := validateRef(spec.Ref); err != nil {
		return nil, err
	}
	workspace, err = validateWorkspace(workspace)
	if err != nil {
		return nil, err
	}

	checkoutPath, err := os.MkdirTemp(workspace, ".repository-")
	if err != nil {
		return nil, fmt.Errorf("create repository checkout: %w", err)
	}
	removeCheckout := true
	defer func() {
		if removeCheckout {
			_ = os.RemoveAll(checkoutPath)
		}
	}()

	cloneArgs := []string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "credential.helper=",
		"-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never",
		"clone",
		"--depth=1",
		"--single-branch",
		"--no-tags",
		"--no-recurse-submodules",
	}
	if spec.Ref != "" {
		cloneArgs = append(cloneArgs, "--branch", spec.Ref)
	}
	cloneArgs = append(cloneArgs, "--", canonicalURL, checkoutPath)

	cloneCtx, cancelClone := context.WithTimeout(ctx, a.cloneTimeout)
	output, err := a.runner.Run(cloneCtx, Command{
		Name: a.gitBinary,
		Args: cloneArgs,
		Dir:  workspace,
		Env:  safeGitEnvironment(),
	})
	if err != nil {
		commandErr := commandError("clone repository", cloneCtx, output, err)
		cancelClone()
		return nil, commandErr
	}
	cancelClone()

	resolveCtx, cancelResolve := context.WithTimeout(ctx, a.resolveTimeout)
	output, err = a.runner.Run(resolveCtx, Command{
		Name: a.gitBinary,
		Args: []string{
			"-c", "core.hooksPath=" + os.DevNull,
			"-c", "credential.helper=",
			"rev-parse", "--verify", "HEAD^{commit}",
		},
		Dir: checkoutPath,
		Env: safeGitEnvironment(),
	})
	if err != nil {
		commandErr := commandError("resolve repository HEAD", resolveCtx, output, err)
		cancelResolve()
		return nil, commandErr
	}
	cancelResolve()

	commitSHA := strings.TrimSpace(string(output))
	if !commitSHAPattern.MatchString(commitSHA) {
		return nil, errors.New("resolve repository HEAD: git returned an invalid commit SHA")
	}
	commitSHA = strings.ToLower(commitSHA)
	ref := spec.Ref
	if ref == "" {
		ref = "HEAD"
	}
	identityPath := strings.TrimPrefix(canonicalURL, "https://github.com/")

	removeCheckout = false
	return &AcquiredRepository{
		Identity: domain.RepositoryIdentity{
			ID:           identityPath,
			CanonicalURL: canonicalURL,
			Ref:          ref,
			CommitSHA:    commitSHA,
		},
		Path:        checkoutPath,
		cleanupPath: checkoutPath,
	}, nil
}

func validateRef(ref string) error {
	if ref == "" {
		return nil
	}
	if ref != strings.TrimSpace(ref) || strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, ".") || strings.HasSuffix(ref, ".") || strings.HasSuffix(ref, "/") {
		return errors.New("repository ref is invalid")
	}
	if strings.ContainsAny(ref, " ~^:?*[\\") || strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.Contains(ref, "@{") || strings.HasSuffix(ref, ".lock") {
		return errors.New("repository ref is invalid")
	}
	for _, character := range ref {
		if character < 0x20 || character == 0x7f {
			return errors.New("repository ref is invalid")
		}
	}
	return nil
}

func validateWorkspace(workspace string) (string, error) {
	if workspace == "" {
		return "", errors.New("workspace is required")
	}
	absolute, err := filepath.Abs(workspace)
	if err != nil {
		return "", fmt.Errorf("resolve workspace: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("inspect workspace: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("workspace must be a directory")
	}
	return absolute, nil
}

func safeGitEnvironment() []string {
	environment := make([]string, 0, len(os.Environ())+5)
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		upperName := strings.ToUpper(name)
		if strings.HasPrefix(upperName, "GIT_") || upperName == "GCM_INTERACTIVE" || upperName == "SSH_ASKPASS" {
			continue
		}
		environment = append(environment, variable)
	}
	return append(environment,
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=Never",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_COUNT=0",
	)
}

func commandError(operation string, ctx context.Context, output []byte, runErr error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s: %w", operation, ctx.Err())
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		return fmt.Errorf("%s: %w", operation, runErr)
	}
	return fmt.Errorf("%s: %w: %s", operation, runErr, message)
}

type execRunner struct {
	maxOutputBytes int64
}

func (r execRunner) Run(ctx context.Context, command Command) ([]byte, error) {
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	cmd.Dir = command.Dir
	cmd.Env = command.Env

	output := &limitedBuffer{remaining: r.maxOutputBytes}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	return output.Bytes(), err
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int64
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	if b.remaining > 0 {
		writeLength := int64(len(data))
		if writeLength > b.remaining {
			writeLength = b.remaining
		}
		_, _ = b.buffer.Write(data[:writeLength])
		b.remaining -= writeLength
	}
	return originalLength, nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}
