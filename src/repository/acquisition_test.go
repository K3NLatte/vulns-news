package repository

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCanonicalizeGitHubURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "canonical", url: "https://github.com/example/project", want: "https://github.com/example/project"},
		{name: "git suffix", url: "https://github.com/example/project.git", want: "https://github.com/example/project"},
		{name: "trailing slash", url: "https://github.com/Example/Project/", want: "https://github.com/Example/Project"},
		{name: "case insensitive scheme and host", url: "HTTPS://GITHUB.COM/example/project", want: "https://github.com/example/project"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := CanonicalizeGitHubURL(test.url)
			if err != nil {
				t.Fatalf("CanonicalizeGitHubURL: %v", err)
			}
			if got != test.want {
				t.Errorf("canonical URL = %q, want %q", got, test.want)
			}
		})
	}
}

func TestCanonicalizeGitHubURLRejectsUnsafeOrNonRepositoryURLs(t *testing.T) {
	t.Parallel()

	urls := []string{
		"http://github.com/example/project",
		"git://github.com/example/project",
		"https://gitlab.com/example/project",
		"https://github.com.evil.test/example/project",
		"https://github.com:443/example/project",
		"https://user:password@github.com/example/project",
		"https://github.com/example/project?tab=readme",
		"https://github.com/example/project?",
		"https://github.com/example/project#readme",
		"https://github.com/example/project#",
		"https://github.com/example/project/issues",
		"https://github.com/example",
		"https://github.com/example/project%2Fother",
		"https://github.com/example--owner/project",
		"https://github.com/example/..",
		" https://github.com/example/project",
	}

	for _, rawURL := range urls {
		rawURL := rawURL
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			if got, err := CanonicalizeGitHubURL(rawURL); err == nil {
				t.Errorf("CanonicalizeGitHubURL(%q) = %q, want error", rawURL, got)
			}
		})
	}
}

func TestAcquireUsesHardenedShallowCloneAndPinsHEAD(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	const commitSHA = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
	var commands []Command
	runner := runnerFunc(func(_ context.Context, command Command) ([]byte, error) {
		commands = append(commands, cloneCommand(command))
		if len(commands) == 1 {
			checkoutPath := command.Args[len(command.Args)-1]
			if info, err := os.Stat(checkoutPath); err != nil || !info.IsDir() {
				t.Fatalf("clone destination was not pre-created as a directory: %v", err)
			}
			return []byte("clone complete"), nil
		}
		return []byte(commitSHA + "\n"), nil
	})

	acquirer, err := NewAcquirer(Config{Runner: runner, GitBinary: "safe-git"})
	if err != nil {
		t.Fatalf("NewAcquirer: %v", err)
	}
	acquired, err := acquirer.Acquire(context.Background(), workspace, RepositorySpec{
		URL: "https://github.com/Example/Project.git",
		Ref: "release/v1",
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	if len(commands) != 2 {
		t.Fatalf("commands = %d, want 2", len(commands))
	}
	clone := commands[0]
	if clone.Name != "safe-git" {
		t.Errorf("clone command = %q, want safe-git", clone.Name)
	}
	wantClonePrefix := []string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "credential.helper=",
		"-c", "protocol.file.allow=never",
		"-c", "protocol.ext.allow=never",
		"clone", "--depth=1", "--single-branch", "--no-tags", "--no-recurse-submodules",
		"--branch", "release/v1", "--", "https://github.com/Example/Project",
	}
	if !slices.Equal(clone.Args[:len(clone.Args)-1], wantClonePrefix) {
		t.Errorf("clone args = %#v, want prefix %#v", clone.Args, wantClonePrefix)
	}
	assertSafeGitEnvironment(t, clone.Env)

	resolve := commands[1]
	if resolve.Dir != acquired.Path {
		t.Errorf("resolve directory = %q, want %q", resolve.Dir, acquired.Path)
	}
	wantResolveArgs := []string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "credential.helper=",
		"rev-parse", "--verify", "HEAD^{commit}",
	}
	if !slices.Equal(resolve.Args, wantResolveArgs) {
		t.Errorf("resolve args = %#v, want %#v", resolve.Args, wantResolveArgs)
	}
	assertSafeGitEnvironment(t, resolve.Env)

	if acquired.Identity.ID != "Example/Project" || acquired.Identity.CanonicalURL != "https://github.com/Example/Project" {
		t.Errorf("identity repository = %#v", acquired.Identity)
	}
	if acquired.Identity.Ref != "release/v1" {
		t.Errorf("identity ref = %q, want release/v1", acquired.Identity.Ref)
	}
	if acquired.Identity.CommitSHA != strings.ToLower(commitSHA) {
		t.Errorf("identity commit = %q", acquired.Identity.CommitSHA)
	}
	if !strings.HasPrefix(acquired.Path, filepath.Clean(workspace)+string(os.PathSeparator)) {
		t.Errorf("checkout path %q is outside workspace %q", acquired.Path, workspace)
	}

	if err := acquired.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(acquired.Path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("checkout still exists after Cleanup: %v", err)
	}
	if err := acquired.Cleanup(); err != nil {
		t.Fatalf("second Cleanup: %v", err)
	}
}

func TestAcquireUsesDefaultBranchWhenRefIsEmpty(t *testing.T) {
	t.Parallel()

	var cloneArgs []string
	runner := runnerFunc(func(_ context.Context, command Command) ([]byte, error) {
		if cloneArgs == nil {
			cloneArgs = append([]string(nil), command.Args...)
			return nil, nil
		}
		return []byte(strings.Repeat("a", 40)), nil
	})
	acquirer, err := NewAcquirer(Config{Runner: runner})
	if err != nil {
		t.Fatalf("NewAcquirer: %v", err)
	}
	acquired, err := acquirer.Acquire(context.Background(), t.TempDir(), RepositorySpec{
		URL: "https://github.com/example/project",
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquired.Cleanup()

	if slices.Contains(cloneArgs, "--branch") {
		t.Errorf("default-branch clone unexpectedly contains --branch: %#v", cloneArgs)
	}
	if acquired.Identity.Ref != "HEAD" {
		t.Errorf("identity ref = %q, want HEAD", acquired.Identity.Ref)
	}
}

func TestAcquireRejectsInvalidRefBeforeRunningCommand(t *testing.T) {
	t.Parallel()

	called := false
	acquirer, err := NewAcquirer(Config{Runner: runnerFunc(func(context.Context, Command) ([]byte, error) {
		called = true
		return nil, nil
	})})
	if err != nil {
		t.Fatalf("NewAcquirer: %v", err)
	}
	_, err = acquirer.Acquire(context.Background(), t.TempDir(), RepositorySpec{
		URL: "https://github.com/example/project",
		Ref: "--upload-pack=malicious",
	})
	if err == nil {
		t.Fatal("Acquire returned nil error")
	}
	if called {
		t.Error("runner was called for an invalid ref")
	}
}

func TestAcquireCleansCheckoutAfterCloneFailure(t *testing.T) {
	t.Parallel()

	var checkoutPath string
	acquirer, err := NewAcquirer(Config{Runner: runnerFunc(func(_ context.Context, command Command) ([]byte, error) {
		checkoutPath = command.Args[len(command.Args)-1]
		return []byte("repository not found"), errors.New("exit status 128")
	})})
	if err != nil {
		t.Fatalf("NewAcquirer: %v", err)
	}
	_, err = acquirer.Acquire(context.Background(), t.TempDir(), RepositorySpec{
		URL: "https://github.com/example/private-project",
	})
	if err == nil || !strings.Contains(err.Error(), "repository not found") {
		t.Fatalf("Acquire error = %v", err)
	}
	if _, statErr := os.Stat(checkoutPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("failed checkout still exists: %v", statErr)
	}
}

func TestAcquireEnforcesCloneTimeoutWithCooperativeRunner(t *testing.T) {
	t.Parallel()

	acquirer, err := NewAcquirer(Config{
		CloneTimeout: 10 * time.Millisecond,
		Runner: runnerFunc(func(ctx context.Context, _ Command) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatalf("NewAcquirer: %v", err)
	}
	_, err = acquirer.Acquire(context.Background(), t.TempDir(), RepositorySpec{
		URL: "https://github.com/example/project",
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire error = %v, want deadline exceeded", err)
	}
}

type runnerFunc func(context.Context, Command) ([]byte, error)

func (f runnerFunc) Run(ctx context.Context, command Command) ([]byte, error) {
	return f(ctx, command)
}

func cloneCommand(command Command) Command {
	command.Args = append([]string(nil), command.Args...)
	command.Env = append([]string(nil), command.Env...)
	return command
}

func assertSafeGitEnvironment(t *testing.T, environment []string) {
	t.Helper()
	values := make(map[string]string, len(environment))
	for _, variable := range environment {
		name, value, _ := strings.Cut(variable, "=")
		values[strings.ToUpper(name)] = value
	}
	for name, want := range map[string]string{
		"GIT_TERMINAL_PROMPT": "0",
		"GCM_INTERACTIVE":     "Never",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_GLOBAL":   os.DevNull,
		"GIT_CONFIG_COUNT":    "0",
	} {
		if values[name] != want {
			t.Errorf("%s = %q, want %q", name, values[name], want)
		}
	}
	if _, exists := values["SSH_ASKPASS"]; exists {
		t.Error("SSH_ASKPASS was inherited")
	}
}
