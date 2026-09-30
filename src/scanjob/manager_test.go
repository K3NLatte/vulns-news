package scanjob

import (
	"context"
	"errors"
	"testing"
	"time"
)

type scannerFunc func(context.Context, Request) (Summary, error)

func (f scannerFunc) Scan(c context.Context, r Request) (Summary, error) { return f(c, r) }

var valid = Request{URL: "https://github.com/example/project"}

func TestQueuedDeadline(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	calls := 0
	m, _ := New(context.Background(), scannerFunc(func(ctx context.Context, _ Request) (Summary, error) {
		calls++
		close(started)
		<-ctx.Done()
		<-release
		return Summary{}, ctx.Err()
	}), 1, 2, 30*time.Millisecond)
	defer m.Close()
	_, _ = m.Submit(valid)
	<-started
	queued, _ := m.Submit(valid)
	time.Sleep(60 * time.Millisecond)
	close(release)
	waitJob(t, m, queued.JobID, "failed")
	m.Close()
	if calls != 1 {
		t.Fatalf("expired queued job invoked scanner: %d", calls)
	}
}

func waitJob(t *testing.T, m *Manager, id, state string) Job {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		j, _ := m.Get(id)
		if j.State == state {
			return j
		}
		time.Sleep(time.Millisecond)
	}
	j, _ := m.Get(id)
	t.Fatalf("want %s: %+v", state, j)
	return j
}
func TestCapacityQueueEvictionAndClose(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	m, err := New(context.Background(), scannerFunc(func(ctx context.Context, _ Request) (Summary, error) {
		started <- struct{}{}
		select {
		case <-release:
			return Summary{CommitSHA: "abc", RefreshComplete: true}, nil
		case <-ctx.Done():
			return Summary{}, ctx.Err()
		}
	}), 1, 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	a, _ := m.Submit(valid)
	<-started
	b, _ := m.Submit(valid)
	if a.JobID == b.JobID || a.RepositoryID == b.RepositoryID {
		t.Fatal("IDs reused")
	}
	if j, _ := m.Get(b.JobID); j.State != "queued" {
		t.Fatal(j)
	}
	if _, err := m.Submit(valid); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	close(release)
	waitJob(t, m, a.JobID, "succeeded")
	waitJob(t, m, b.JobID, "succeeded")
	j, _ := m.Get(a.JobID)
	j.Summary.CommitSHA = "mutated"
	if j, _ = m.Get(a.JobID); j.Summary.CommitSHA != "abc" {
		t.Fatal("mutable snapshot")
	}
	if _, err := m.Submit(valid); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get(a.JobID); ok {
		t.Fatal("oldest not evicted")
	}
	m.Close()
	if _, err := m.Submit(valid); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
func TestFailureTimeoutAndCancellation(t *testing.T) {
	for _, mode := range []string{"failure", "timeout", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			m, _ := New(context.Background(), scannerFunc(func(ctx context.Context, _ Request) (Summary, error) {
				close(started)
				if mode == "failure" {
					return Summary{}, errors.New("secret internal stderr")
				}
				<-ctx.Done()
				return Summary{}, ctx.Err()
			}), 1, 2, 40*time.Millisecond)
			defer m.Close()
			j, _ := m.Submit(valid)
			<-started
			state := "failed"
			message := "scan failed"
			if mode == "cancel" {
				_, _ = m.Submit(valid)
				m.Close()
				state = "canceled"
				message = "scan canceled"
			}
			if mode == "timeout" {
				message = "scan timed out"
			}
			if got := waitJob(t, m, j.JobID, state); got.Error != message {
				t.Fatal(got)
			}
		})
	}
}
func TestValidation(t *testing.T) {
	for _, url := range []string{"http://github.com/a/b", "https://github.com.evil/a/b", "https://u:p@github.com/a/b", "https://github.com:443/a/b", "https://github.com/a/b?", "https://github.com/a/b#", "https://github.com/a/b/tree/main", "https://github.com/a/%62", "file:///tmp/repo", ""} {
		if _, err := Validate(Request{URL: url}); err == nil {
			t.Errorf("accepted %q", url)
		}
	}
	for _, ref := range []string{"-main", "../main", "main.lock", "a/.b", "a//b", "a/", "a..b", "@", "a@{b}", "a\n", "a b", "a:b", "a\\b"} {
		r := valid
		r.Ref = ref
		if _, err := Validate(r); err == nil {
			t.Errorf("accepted %q", ref)
		}
	}
	for _, ref := range []string{"", "main", "feature/local-llm", "v1.2.3"} {
		r := valid
		r.Ref = ref
		if _, err := Validate(r); err != nil {
			t.Fatal(err)
		}
	}
}
