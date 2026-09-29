package reportstore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// Store はSQLiteへの接続を1つ保持する。サーバー起動時に開き、終了時にCloseする。
// 同時の呼び出しはdatabase/sqlが順番に処理し、待機中もcontextで中止できる。
// HTTPや認可の処理はここでは扱わない。
type Store struct{ db *sql.DB }

// Open はローカルDBファイル（または:memory:）を開き、スキーマを適用する。
// 親ディレクトリは事前に作成する。pathにはサーバー設定のパスを渡し、
// URLや利用者が入力したリポジトリIDを使わない。未知のスキーマ版は削除せずエラーにする。
func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" || strings.HasPrefix(path, "file:") {
		return nil, fmt.Errorf("%w: expected a local database filename", ErrInvalid)
	}
	dsn := path
	if path != ":memory:" {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("database path: %w", err)
		}
		uriPath := filepath.ToSlash(absolute)
		// Windowsのドライブ文字をホスト名と誤認させないよう、file:///C:/...の形にする。
		if !strings.HasPrefix(uriPath, "/") {
			uriPath = "/" + uriPath
		}
		dsn = (&url.URL{Scheme: "file", Path: uriPath}).String()
	}
	// 中断後にdatabase/sqlが接続を張り直す場合があるため、
	// 初期化時の接続だけでなく、すべての接続にドライバー経由で設定を適用する。
	params := url.Values{}
	for _, pragma := range []string{
		"busy_timeout(5000)", "foreign_keys(ON)",
		"journal_mode(WAL)", "synchronous(FULL)",
	} {
		params.Add("_pragma", pragma)
	}
	// このパッケージのトランザクションはすべて書き込みを伴う。
	// 読み取り前に書き込みロックを確保し、複数Storeからの同時更新を待機させる。
	// 読み取り後にロックを昇格させる方式では、競合時に待機せず失敗するため。
	params.Set("_txlock", "immediate")
	dsn += "?" + params.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open reports: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db}
	if err := s.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS reportstore_schema (
		version INTEGER PRIMARY KEY
	) STRICT`); err != nil {
		return fmt.Errorf("create schema version table: %w", err)
	}
	var version, count int
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(version), 0), count(*) FROM reportstore_schema").Scan(&version, &count); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if count == 0 {
		// IF NOT EXISTSを付けず、版管理のない既存のreportsテーブルはエラーにする。
		// 試作スキーマを無条件に引き継いだり、既存データを破壊したりしない。
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return fmt.Errorf("create reports schema: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO reportstore_schema (version) VALUES (3)"); err != nil {
			return fmt.Errorf("record schema version: %w", err)
		}
	} else {
		if count != 1 || version < 1 || version > 3 {
			return fmt.Errorf("unsupported report schema version %d (rows %d)", version, count)
		}
		if version == 1 {
			if err := migrateVersion1(ctx, tx); err != nil {
				return fmt.Errorf("migrate report schema v1: %w", err)
			}
			version = 2
		}
		if version == 2 {
			if err := migrateVersion2(ctx, tx); err != nil {
				return fmt.Errorf("migrate report schema v2: %w", err)
			}
		}
	}
	if _, err := tx.ExecContext(ctx, "SELECT "+reportColumns+" FROM reports LIMIT 0"); err != nil {
		return fmt.Errorf("check reports schema: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

// v2では元データの日時欠損を許容する。同じトランザクション内でテーブルを再作成し、
// レポートID・本文・保存日時・削除済みIDを含む採番の最大値を維持する。
func migrateVersion1(ctx context.Context, tx *sql.Tx) error {
	var sequence int64
	if err := tx.QueryRowContext(ctx, "SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'reports'), 0)").Scan(&sequence); err != nil {
		return err
	}
	for _, statement := range []string{
		"ALTER TABLE reports RENAME TO reports_v1",
		"DROP INDEX reports_by_context",
		schema,
		"INSERT INTO reports (" + reportColumns + ") SELECT " + reportColumns + " FROM reports_v1",
		"DROP TABLE reports_v1",
		"DELETE FROM sqlite_sequence WHERE name = 'reports'",
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sqlite_sequence (name, seq)
		SELECT 'reports', max(?, coalesce(max(report_id), 0)) FROM reports`, sequence); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE reportstore_schema SET version = 2 WHERE version = 1")
	return err
}

// v3では履歴を統合せず、同じ時刻を表す日時文字列を共通の表記へ正規化する。
// 一定件数ずつ読み、読み取りカーソルを閉じてから対象行を更新する。
func migrateVersion2(ctx context.Context, tx *sql.Tx) error {
	type dates struct {
		id                    int64
		revision, cve, public sql.NullString
	}
	var afterID int64
	for {
		rows, err := tx.QueryContext(ctx, `SELECT report_id, vulnerability_revision, cve_revision, published_at
			FROM reports WHERE report_id > ? ORDER BY report_id LIMIT 256`, afterID)
		if err != nil {
			return err
		}
		batch := make([]dates, 0, 256)
		for rows.Next() {
			var row dates
			if err := rows.Scan(&row.id, &row.revision, &row.cve, &row.public); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, row)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		for _, row := range batch {
			canonical := make([]any, 3)
			for i, value := range []sql.NullString{row.revision, row.cve, row.public} {
				if value.Valid && value.String == "" {
					return fmt.Errorf("report %d has an empty stored date", row.id)
				}
				normalized, err := canonicalTimestamp(value.String)
				if err != nil {
					return fmt.Errorf("report %d date: %w", row.id, err)
				}
				canonical[i] = nullText(normalized)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE reports SET vulnerability_revision = ?, cve_revision = ?, published_at = ?
				WHERE report_id = ?`, canonical[0], canonical[1], canonical[2], row.id); err != nil {
				return err
			}
			afterID = row.id
		}
	}
	_, err := tx.ExecContext(ctx, "UPDATE reportstore_schema SET version = 3 WHERE version = 2")
	return err
}

func (s *Store) Close() error { return s.db.Close() }

const reportColumns = `report_id, repository_id, repository_commit,
 vulnerability_id, vulnerability_revision, cve_id, cve_revision,
 published_at, severity, cvss, status, relevance, report_json, stored_at`

const insertReport = `INSERT INTO reports (
 repository_id, repository_commit, vulnerability_id, vulnerability_revision,
 cve_id, cve_revision, published_at, severity, cvss, status, relevance, report_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ` + reportColumns

func inputArgs(input Input) []any {
	return []any{
		input.RepositoryID, input.RepositoryCommit, input.VulnerabilityID, nullText(input.VulnerabilityRevision),
		nullText(input.CVEID), nullText(input.CVERevision), nullText(input.PublishedAt),
		nullText(input.Severity), input.CVSS, input.Status, input.Relevance, string(input.Body),
	}
}

func nullText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

type rowScanner interface{ Scan(...any) error }

func scanReport(row rowScanner) (Report, error) {
	var report Report
	var cveID, cveRevision, severity, vulnerabilityRevision, publishedAt sql.NullString
	var cvss sql.NullFloat64
	var body string
	err := row.Scan(&report.ID, &report.RepositoryID, &report.RepositoryCommit,
		&report.VulnerabilityID, &vulnerabilityRevision, &cveID, &cveRevision,
		&publishedAt, &severity, &cvss, &report.Status, &report.Relevance, &body, &report.StoredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, fmt.Errorf("read report: %w", err)
	}
	report.CVEID, report.CVERevision, report.Severity = cveID.String, cveRevision.String, severity.String
	report.VulnerabilityRevision, report.PublishedAt = vulnerabilityRevision.String, publishedAt.String
	if cvss.Valid {
		report.CVSS = &cvss.Float64
	}
	report.Body = []byte(body)
	return report, nil
}

// Create は解析結果を1件追加する。再解析時も履歴を残すためCreateを使う。
func (s *Store) Create(ctx context.Context, input Input) (Report, error) {
	input, err := canonicalizeInputTimes(input)
	if err != nil {
		return Report{}, err
	}
	if err := validateInput(input); err != nil {
		return Report{}, err
	}
	report, err := scanReport(s.db.QueryRowContext(ctx, insertReport, inputArgs(input)...))
	if err != nil {
		return Report{}, fmt.Errorf("create report: %w", err)
	}
	return report, nil
}

func validID(id int64) error {
	if id <= 0 {
		return fmt.Errorf("%w: report ID must be positive", ErrInvalid)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, id int64) (Report, error) {
	if err := validID(id); err != nil {
		return Report{}, err
	}
	return scanReport(s.db.QueryRowContext(ctx, "SELECT "+reportColumns+" FROM reports WHERE report_id = ?", id))
}

// GetLatest はunrelatedの判定も返す。呼び出し側でその理由を確認できる。
func (s *Store) GetLatest(ctx context.Context, key ContextKey) (Report, error) {
	key, err := canonicalizeContextKey(key)
	if err != nil {
		return Report{}, err
	}
	if err := validateKey(key); err != nil {
		return Report{}, err
	}
	return scanReport(s.db.QueryRowContext(ctx, "SELECT "+reportColumns+` FROM reports
		WHERE repository_id = ? AND repository_commit = ?
		AND vulnerability_id = ? AND vulnerability_revision IS ?
		ORDER BY report_id DESC LIMIT 1`,
		key.RepositoryID, key.RepositoryCommit, key.VulnerabilityID, nullText(key.VulnerabilityRevision)))
}

// ListLatest は該当結果がなければ空のスライスを返す（nilにはしない）。
// 最新結果を選んだ後にページ条件とunrelatedの除外を適用し、古い結果の再表示を防ぐ。
// 複数回の呼び出しをまたいで一覧の状態を固定するものではない。
func (s *Store) ListLatest(ctx context.Context, options ListOptions) ([]Report, error) {
	if strings.TrimSpace(options.RepositoryID) == "" || strings.TrimSpace(options.RepositoryCommit) == "" ||
		options.Limit < 0 || options.Limit > 200 || options.BeforeID < 0 {
		return nil, fmt.Errorf("%w: repository snapshot and valid pagination are required", ErrInvalid)
	}
	limit := options.Limit
	if limit == 0 {
		limit = 50
	}
	query := `WITH latest AS (
		SELECT max(report_id) AS report_id FROM reports
		WHERE repository_id = ? AND repository_commit = ?
		GROUP BY vulnerability_id, vulnerability_revision
	) SELECT ` + reportColumns + ` FROM reports
	WHERE report_id IN (SELECT report_id FROM latest)
	AND (? = 0 OR report_id < ?) AND (? OR relevance <> 'unrelated')
	ORDER BY report_id DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, options.RepositoryID, options.RepositoryCommit,
		options.BeforeID, options.BeforeID, options.IncludeUnrelated, limit)
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}
	defer rows.Close()
	reports := make([]Report, 0)
	for rows.Next() {
		report, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reports: %w", err)
	}
	return reports, nil
}

// Update は既存レポートの変更可能な項目を置き換える。
// ID・stored_at・ContextKeyは変更できない。既存結果の訂正に使い、新しい解析履歴は作らない。
// 同時更新では最後に成功した更新が残る。編集競合の検出が必要な場合は、
// 編集機能を公開する前に呼び出し側で制御する。
func (s *Store) Update(ctx context.Context, id int64, input Input) (Report, error) {
	if err := validID(id); err != nil {
		return Report{}, err
	}
	input, err := canonicalizeInputTimes(input)
	if err != nil {
		return Report{}, err
	}
	if err := validateInput(input); err != nil {
		return Report{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Report{}, fmt.Errorf("begin report update: %w", err)
	}
	defer tx.Rollback()
	old, err := scanReport(tx.QueryRowContext(ctx, "SELECT "+reportColumns+" FROM reports WHERE report_id = ?", id))
	if err != nil {
		return Report{}, err
	}
	if old.ContextKey != input.ContextKey {
		return Report{}, fmt.Errorf("%w: report context cannot change", ErrInvalid)
	}
	report, err := scanReport(tx.QueryRowContext(ctx, `UPDATE reports SET
		cve_id = ?, cve_revision = ?, published_at = ?, severity = ?, cvss = ?,
		status = ?, relevance = ?, report_json = ? WHERE report_id = ? RETURNING `+reportColumns,
		nullText(input.CVEID), nullText(input.CVERevision), nullText(input.PublishedAt), nullText(input.Severity),
		input.CVSS, input.Status, input.Relevance, string(input.Body), id))
	if err != nil {
		return Report{}, fmt.Errorf("update report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Report{}, fmt.Errorf("commit report update: %w", err)
	}
	return report, nil
}

// Delete は指定したレポート1件だけを物理削除する。
// 最新行を削除するとGetLatest/ListLatestでは過去の行が最新になる。非表示設定ではない。
func (s *Store) Delete(ctx context.Context, id int64) error {
	if err := validID(id); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, "DELETE FROM reports WHERE report_id = ?", id)
	if err != nil {
		return fmt.Errorf("delete report: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("deleted row count: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
