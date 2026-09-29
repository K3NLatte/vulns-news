package reportstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestConnectionReplacementPreservesSettingsAndReports(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw, err := os.ReadFile("testdata/feed-item.json")
	if err != nil {
		t.Fatal(err)
	}
	input, err := FromFeedJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}

	for _, phase := range []string{"initial connection", "replacement connection"} {
		t.Run(phase, func(t *testing.T) {
			conn, err := store.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			assertConnectionSettings(t, ctx, conn)
		})

		got, err := store.Get(ctx, original.ID)
		if err != nil {
			t.Fatalf("%s: read existing report: %v", phase, err)
		}
		if !reflect.DeepEqual(got, original) {
			t.Errorf("%s: existing report changed:\nwant: %#v\n got: %#v", phase, original, got)
		}

		if phase == "initial connection" {
			conn, err := store.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Raw が ErrBadConn を返すと、database/sql は実際の接続を破棄する。
			// これにより、goroutine やタイムアウトのタイミングに依存せず、
			// キャンセルやドライバーの障害に伴う接続の置き換えを再現する。
			err = conn.Raw(func(any) error { return driver.ErrBadConn })
			_ = conn.Close()
			if !errors.Is(err, driver.ErrBadConn) {
				t.Fatalf("discard connection: got %v, want driver.ErrBadConn", err)
			}
			if got := store.db.Stats().OpenConnections; got != 0 {
				t.Fatalf("discarded connection is still pooled: open connections = %d", got)
			}
		}
	}

	created, err := store.Create(ctx, input)
	if err != nil {
		t.Fatalf("create after connection replacement: %v", err)
	}
	if created.ID <= original.ID {
		t.Errorf("replacement reset report IDs: new=%d original=%d", created.ID, original.ID)
	}
	got, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("read report created after connection replacement: %v", err)
	}
	if !reflect.DeepEqual(got, created) {
		t.Errorf("report created after connection replacement changed:\nwant: %#v\n got: %#v", created, got)
	}
}

func assertConnectionSettings(t *testing.T, ctx context.Context, conn *sql.Conn) {
	t.Helper()
	for _, setting := range []struct {
		name string
		want string
	}{
		{"busy_timeout", "5000"},
		{"foreign_keys", "1"},
		{"journal_mode", "wal"},
		{"synchronous", "2"},
	} {
		var got string
		if err := conn.QueryRowContext(ctx, "PRAGMA "+setting.name).Scan(&got); err != nil {
			t.Errorf("read %s: %v", setting.name, err)
			continue
		}
		if got != setting.want {
			t.Errorf("%s = %q, want %q", setting.name, got, setting.want)
		}
	}
}
