package osv

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"vulns-news/src/domain"
)

func TestCacheAcrossCVEs(t *testing.T) {
	var calls atomic.Int32
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"vulns":[{"id":"GHSA-first","aliases":["CVE-2025-10000"]},{"id":"GHSA-last","aliases":["CVE-2025-10199"]}]}`)
	})
	for i := 0; i < 200; i++ {
		v := domain.NormalizedVulnerability{ID: fmt.Sprintf("CVE-2025-%d", 10000+i)}
		got, err := c.Enrich(context.Background(), profile("npm", "1.2.3"), v)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if i == 0 || i == 199 {
			want = 1
		}
		if len(got.Affected) != want {
			t.Fatalf("CVE %s: %+v", v.ID, got)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("queries=%d, want 1", calls.Load())
	}
}

func TestCacheKeysAndEmptyResponses(t *testing.T) {
	var calls atomic.Int32
	c := client(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, `{}`) })
	for _, p := range []domain.RepositoryProfile{
		profile("Go", "v1.2.3"), profile("go", "v1.2.3"),
		profile("npm", "1.2.3"), profile("npm", "1.2.4"),
		{Components: []domain.Component{{Ecosystem: "npm", Name: "other", Version: "1.2.3"}}},
		profile("pypi", "1.2.3"), profile("PyPI", "1.2.3"),
	} {
		for i := 0; i < 2; i++ {
			if _, err := c.Enrich(context.Background(), p, vulnerability()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if calls.Load() != 5 {
		t.Fatalf("queries=%d, want 5 distinct canonical keys", calls.Load())
	}
}

func TestCacheConcurrentQueriesAndWaiterCancellation(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	c := client(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		io.WriteString(w, `{"vulns":[{"id":"CVE-2025-12345"}]}`)
	})
	// Release before the server cleanup even if an assertion fails.
	var once sync.Once
	defer once.Do(func() { close(release) })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := c.Enrich(context.Background(), profile("npm", "1.2.3"), vulnerability()); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan error, 1)
	go func() { _, err := c.Enrich(ctx, profile("npm", "1.2.3"), vulnerability()); waiter <- err }()
	cancel()
	if err := <-waiter; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.Enrich(context.Background(), profile("npm", "1.2.3"), vulnerability())
			if err != nil || len(got.Affected) != 1 {
				t.Errorf("result=%+v err=%v", got, err)
			}
		}()
	}
	once.Do(func() { close(release) })
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent queries=%d", calls.Load())
	}
}

func TestCacheFailuresAndRetryAfterCancellation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"HTTP", "", 503}, {"decode", "{", 200}, {"pagination", `{"next_page_token":"next"}`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c := client(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			for i := 0; i < 2; i++ {
				if _, err := c.Enrich(context.Background(), profile("npm", "1.2.3"), vulnerability()); err == nil {
					t.Fatal("cached failure became success")
				}
			}
			if calls.Load() != 1 {
				t.Fatal(calls.Load())
			}
		})
	}
	t.Run("cancelled owner is not cached", func(t *testing.T) {
		var calls atomic.Int32
		entered := make(chan struct{})
		c, err := NewClient(Config{HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				close(entered)
				<-r.Context().Done()
				return nil, r.Context().Err()
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		})}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := c.Enrich(ctx, profile("npm", "1.2.3"), vulnerability()); done <- err }()
		<-entered
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if _, err := c.Enrich(context.Background(), profile("npm", "1.2.3"), vulnerability()); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 {
			t.Fatal(calls.Load())
		}
	})
}

func TestCacheBounds(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		count      int
	}{
		{"entries", `{}`, maxCacheEntries},
		{"bytes", `{}` + strings.Repeat(" ", maxBodyBytes-2), maxCacheBytes / maxBodyBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			c := client(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, tc.body) })
			for i := 0; i <= tc.count; i++ {
				p := profile("npm", "1.2.3")
				p.Components[0].Name = fmt.Sprintf("package-%d", i)
				_, err := c.Enrich(context.Background(), p, vulnerability())
				if i < tc.count && err != nil {
					t.Fatal(err)
				}
				if i == tc.count && !errors.Is(err, ErrLimit) {
					t.Fatalf("overflow error=%v", err)
				}
			}
			c.mu.Lock()
			entries, bytes := len(c.cache), c.cacheBytes
			c.mu.Unlock()
			if entries > maxCacheEntries || bytes > maxCacheBytes {
				t.Fatalf("cache exceeded bounds: %d entries, %d bytes", entries, bytes)
			}
			// Existing successful queries remain available after capacity exhaustion.
			p := profile("npm", "1.2.3")
			p.Components[0].Name = "package-0"
			before := calls.Load()
			if _, err := c.Enrich(context.Background(), p, vulnerability()); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != before {
				t.Fatal("evicted cached query")
			}
		})
	}
}

func TestCacheIsolation(t *testing.T) {
	var calls atomic.Int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"vulns":[{"id":"GHSA-example","aliases":["CVE-2025-12345"]}]}`)
	}
	first, second := client(t, handler), client(t, handler)
	q, _ := componentQuery(profile("npm", "1.2.3").Components[0])
	r, err := first.query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	r.Vulns[0].ID = "changed"
	r.Vulns[0].Aliases[0] = "changed"
	for _, c := range []*Client{first, second} {
		got, err := c.Enrich(context.Background(), profile("npm", "1.2.3"), vulnerability())
		if err != nil || len(got.Affected) != 1 {
			t.Fatalf("result=%+v err=%v", got, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("cache leaked between clients: queries=%d", calls.Load())
	}
}
