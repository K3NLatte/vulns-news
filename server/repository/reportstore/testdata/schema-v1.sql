-- 移行テスト用のスキーマv1。版管理のない旧試作DBには直接適用しない。
CREATE TABLE reports (
    report_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id      TEXT NOT NULL CHECK (length(trim(repository_id)) > 0),
    repository_commit  TEXT NOT NULL CHECK (length(trim(repository_commit)) > 0),
    vulnerability_id   TEXT NOT NULL CHECK (length(trim(vulnerability_id)) > 0),
    vulnerability_revision TEXT NOT NULL CHECK (length(trim(vulnerability_revision)) > 0),
    cve_id             TEXT CHECK (cve_id IS NULL OR length(trim(cve_id)) > 0),
    cve_revision       TEXT CHECK (cve_revision IS NULL OR length(trim(cve_revision)) > 0),
    published_at       TEXT NOT NULL CHECK (length(trim(published_at)) > 0),
    severity           TEXT CHECK (severity IS NULL OR length(trim(severity)) > 0),
    cvss               REAL CHECK (cvss IS NULL OR cvss BETWEEN 0 AND 10),
    status             TEXT NOT NULL CHECK (status IN ('screened', 'analyzed')),
    relevance          TEXT NOT NULL CHECK (relevance IN ('related', 'possibly_related', 'unrelated', 'unknown')),
    report_json        TEXT NOT NULL,
    stored_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),

    -- feed.Item全体ではなく本文のJSONを保存する。必須キーの欠損は拒否する。
    CONSTRAINT valid_report_body CHECK (
        CASE WHEN json_valid(report_json) THEN COALESCE(
            json_type(report_json) = 'object'
            AND json_type(report_json, '$.screening_reason') = 'text'
            AND json_type(report_json, '$.matches') = 'array'
            AND (json_type(report_json, '$.applicability') = 'object'
                OR (relevance = 'unrelated'
                    AND COALESCE(json_type(report_json, '$.applicability'), 'null') = 'null'))
            AND json_type(report_json, '$.evidence') = 'array'
            AND json_array_length(report_json, '$.evidence') > 0
            AND (relevance <> 'unrelated'
                OR (json_type(report_json, '$.screening_evidence_ids') = 'array'
                    AND json_array_length(report_json, '$.screening_evidence_ids') > 0)),
            0
        ) ELSE 0 END
    ),
    -- 識別情報と状態はカラムに保存し、generationは保存しない。
    -- json_typeのSQL NULLはキーの欠損を表す。明示的なJSON nullも拒否する。
    CONSTRAINT no_duplicate_metadata CHECK (
        CASE WHEN json_valid(report_json) THEN
            json_type(report_json, '$.report_id') IS NULL
            AND json_type(report_json, '$.repository_id') IS NULL
            AND json_type(report_json, '$.repository_commit') IS NULL
            AND json_type(report_json, '$.vulnerability_id') IS NULL
            AND json_type(report_json, '$.vulnerability_revision') IS NULL
            AND json_type(report_json, '$.cve_id') IS NULL
            AND json_type(report_json, '$.cve_revision') IS NULL
            AND json_type(report_json, '$.published_at') IS NULL
            AND json_type(report_json, '$.severity') IS NULL
            AND json_type(report_json, '$.cvss') IS NULL
            AND json_type(report_json, '$.status') IS NULL
            AND json_type(report_json, '$.relevance') IS NULL
            AND json_type(report_json, '$.stored_at') IS NULL
            AND json_type(report_json, '$.generation') IS NULL
            AND json_type(report_json, '$.applicability.repository_id') IS NULL
            AND json_type(report_json, '$.applicability.repository_commit') IS NULL
            AND json_type(report_json, '$.applicability.vulnerability_id') IS NULL
            AND json_type(report_json, '$.applicability.vulnerability_revision') IS NULL
        ELSE 0 END
    ),
    -- CVE以外のアドバイザリも、それぞれの脆弱性IDと更新日時を持つ。
    -- GoのCVEゼロ日時（0001-01-01T00:00:00Z）はNULLへ変換する。
    CONSTRAINT valid_cve_metadata CHECK (
        (cve_id IS NULL AND cve_revision IS NULL)
        OR (cve_id IS NOT NULL AND cve_revision IS NOT NULL)
    ),
    -- 現在の解析処理では、一次判定のみの状態と詳細解析済みの状態を扱う。
    CONSTRAINT valid_processing_state CHECK (
        (status = 'screened' AND relevance IN ('possibly_related', 'unrelated', 'unknown'))
        OR (status = 'analyzed' AND relevance = 'related')
    ),
    CONSTRAINT valid_analysis_presence CHECK (
        CASE WHEN json_valid(report_json) THEN COALESCE(
            (status = 'screened'
                AND COALESCE(json_type(report_json, '$.summary'), 'null') = 'null'
                AND COALESCE(json_type(report_json, '$.repository_impact'), 'null') = 'null')
            OR (status = 'analyzed'
                AND json_type(report_json, '$.summary') = 'object'
                AND json_type(report_json, '$.repository_impact') = 'object'),
            0
        ) ELSE 0 END
    )
) STRICT;

CREATE INDEX reports_by_context
    ON reports (repository_id, repository_commit, vulnerability_id, vulnerability_revision, report_id DESC);

-- 再解析は行を追加する。同じ対象の履歴を許容し、自動キャッシュ再利用は行わない。
-- feed.Itemの識別情報を検証してから、カラムと重複する情報を本文から除く。
-- 保存する本文全体の検証はGoの変換処理で行う。
-- unrelatedも保存する場合は、フィードから除外する前の入力と一次判定を使う。
-- 保存行がないことを「関連なし」の判定として扱わない。
