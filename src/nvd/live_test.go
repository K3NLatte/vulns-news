package nvd

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestFetchLive makes real unauthenticated NVD requests only when opted in.
func TestFetchLive(t *testing.T) {
	if os.Getenv("NVD_LIVE_TEST") != "1" {
		t.Skip("set NVD_LIVE_TEST=1 to enable live NVD requests")
	}
	count := 1
	if value := os.Getenv("NVD_LIVE_COUNT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 200 {
			t.Fatal("NVD_LIVE_COUNT must be an integer between 1 and 200")
		}
		count = parsed
	}
	// Deliberately do not read any API key from the environment.
	client, err := NewAnalysisClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	items, err := client.Fetch(ctx, count)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != count {
		t.Fatal("live NVD result count does not match requested count")
	}
	t.Logf("count=%d first=%s last=%s", len(items), items[0].ID, items[len(items)-1].ID)
}
