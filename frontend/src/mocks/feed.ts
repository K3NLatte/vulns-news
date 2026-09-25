import type { FeedItem } from '../types/feed'

/** Every product, advisory, score, analysis, and dependency below is fictional. */
export const mockGeneratedAt = '2026-09-24T03:00:00.000Z'

const reference = (id: number, title: string): FeedItem['sources'] => [{
  name: `CWE-${id}：${title}`,
  url: `https://cwe.mitre.org/data/definitions/${id}.html`,
  kind: 'reference',
}]

export const mockFeed: FeedItem[] = [
  {
    id: 'demo-001',
    advisoryId: 'DEMO-2026-001',
    title: '認証前のテンプレート評価により任意の処理が実行される可能性',
    product: 'SampleView Engine',
    affectedVersions: '3.0.0以上、3.4.2未満',
    fixedVersion: '3.4.2',
    severity: 'critical',
    cvss: 9.8,
    publishedAt: '2026-09-24T01:30:00.000Z',
    updatedAt: '2026-09-24T02:00:00.000Z',
    summary: '外部入力がテンプレートとして評価される問題です。プレビュー機能を公開している構成では、認証前の入力が評価処理に到達する可能性があります。',
    exploitation: 'observed',
    affectedComponent: 'sampleview-engine / preview renderer',
    remediation: ['修正版3.4.2へ更新する。', '更新までプレビュー機能への外部アクセスを制限する。', '外部入力をテンプレート文字列として渡す箇所を確認する。'],
    analysis: {
      summary: '依存関係の一致だけでなく、プレビュー機能を公開しているかの確認が必要です。',
      evidence: '3.4.0ではプレビュー入力がテンプレート評価へ渡ります。公開設定と利用箇所の確認が必要です。',
      confidence: 'medium',
    },
    relevance: { kind: 'direct', reason: '直接依存が影響範囲に含まれます。プレビュー機能の利用有無は未確認です。', score: 74, priority: 'high', packageName: 'sampleview-engine', installedVersion: '3.4.0' },
    proofOfConcept: {
      language: 'http',
      code: `POST /preview HTTP/1.1
Host: example.invalid
Content-Type: application/json

{"template":"{{ 7 * 7 }}"}`,
      conditions: ['プレビュー機能が外部入力をテンプレートとして受け取ること。', '文字列がそのまま表示されるか、計算結果の49として評価されるかを確認する。'],
    },
    sources: reference(94, 'コード生成の制御不備'),
  },
  {
    id: 'demo-002',
    advisoryId: 'DEMO-2026-002',
    title: '共有キャッシュのキー衝突で別ユーザーの応答が返る',
    product: 'DemoCache Gateway',
    affectedVersions: '2.2.0以上、2.6.1未満',
    fixedVersion: '2.6.1',
    severity: 'high',
    cvss: 8.1,
    publishedAt: '2026-09-24T00:20:00.000Z',
    updatedAt: '2026-09-24T00:45:00.000Z',
    summary: '認証状態を共有キャッシュのキーに含めない構成で、別ユーザー向けの応答が再利用される問題です。個人情報を含むページをキャッシュしているかが確認点になります。',
    exploitation: 'poc',
    affectedComponent: 'democache-gateway / response cache',
    remediation: ['修正版2.6.1へ更新する。', '認証済み応答を共有キャッシュから除外する。', '既存のキャッシュを破棄し、ユーザー間で応答が共有されないかを確認する。'],
    analysis: {
      summary: 'Webフレームワークから間接的に取り込まれる場合があります。キャッシュの設定次第で影響が変わります。',
      evidence: '2.5.0の共有キャッシュには認証状態の区別がありません。機密データをキャッシュする設定かは未確認です。',
      confidence: 'medium',
    },
    relevance: { kind: 'transitive', reason: 'Webフレームワーク経由で取り込まれます。キャッシュ設定を確認してください。', score: 92, priority: 'urgent', packageName: 'democache-gateway', installedVersion: '2.5.0' },
    proofOfConcept: {
      language: 'http',
      code: `GET /account/summary HTTP/1.1
Host: example.invalid
Authorization: Bearer USER_A

GET /account/summary HTTP/1.1
Host: example.invalid
Authorization: Bearer USER_B`,
      conditions: ['異なる2ユーザーと共有キャッシュを使用すること。', 'USER_AとUSER_Bは管理下の検証アカウントへ置き換える。', '2件目の応答に1件目のユーザー固有情報が含まれないことを確認する。'],
    },
    sources: reference(524, '機密情報を含むキャッシュ'),
  },
  {
    id: 'demo-003',
    advisoryId: 'DEMO-2026-003',
    title: '添付ファイルのパス検証が不十分で保存先の外へ書き込める',
    product: 'TrialAttachment',
    affectedVersions: '1.0.0以上、1.8.4未満',
    fixedVersion: '1.8.4',
    severity: 'high',
    cvss: 8.8,
    publishedAt: '2026-09-23T22:10:00.000Z',
    updatedAt: '2026-09-24T01:00:00.000Z',
    summary: '添付ファイル処理で、利用者が指定したファイル名の検証に漏れがあります。認証済み利用者にアップロードを許可している構成が確認対象です。',
    exploitation: 'not-observed',
    affectedComponent: 'trial-attachment / file storage',
    remediation: ['修正版1.8.4へ更新する。', '保存ファイル名はサーバー側で生成する。', '正規化後の保存先が許可したディレクトリ内にあるかを検証する。'],
    analysis: {
      summary: '影響バージョンではアップロード処理の出力先検証が不足しています。機能を無効化している構成の到達性は別途確認が必要です。',
      evidence: '1.8.1では保存先の正規化後にディレクトリの境界を確認していません。アップロード経路の確認が必要です。',
      confidence: 'high',
    },
    relevance: { kind: 'direct', reason: '直接依存1.8.1が影響範囲に含まれます。', score: 98, priority: 'urgent', packageName: 'trial-attachment', installedVersion: '1.8.1' },
    proofOfConcept: {
      language: 'http',
      code: `POST /attachments HTTP/1.1
Host: example.invalid
Content-Type: application/json

{"filename":"../boundary-check.txt","content":"boundary-check"}`,
      conditions: ['アップロード機能にアクセスできる検証アカウントを使用すること。', '保存先を隔離し、既存ファイルを含まないディレクトリで確認する。', 'リクエストが拒否され、許可ディレクトリの外にファイルが作られないことを確認する。'],
    },
    sources: reference(22, 'パストラバーサル'),
  },
  {
    id: 'demo-004',
    advisoryId: 'DEMO-2026-004',
    title: 'ログ検索のクエリ組み立てにSQLインジェクションの不備',
    product: 'ExampleLog Search',
    affectedVersions: '4.0.0以上、4.2.3未満',
    fixedVersion: '4.2.3',
    severity: 'critical',
    cvss: 9.1,
    publishedAt: '2026-09-23T09:15:00.000Z',
    updatedAt: '2026-09-23T11:30:00.000Z',
    summary: 'ログ検索サービスが、一部の検索条件をSQLへ直接連結します。ログ閲覧権限を持つユーザーが、許可範囲外のデータを参照できる可能性があります。',
    exploitation: 'poc',
    affectedComponent: 'examplelog-search / query builder',
    remediation: ['修正版4.2.3へ更新する。', '検索条件にはパラメーター化クエリを使用する。', 'DB接続ユーザーの権限を必要な範囲に絞る。'],
    analysis: {
      summary: '検索APIに到達できる利用者とDB権限の組み合わせで影響を評価します。',
      evidence: '検索条件の一部でパラメーター化が行われていません。DB接続ユーザーの権限によって参照範囲が変わります。',
      confidence: 'medium',
    },
    sources: reference(89, 'SQLインジェクション'),
  },
  {
    id: 'demo-005',
    advisoryId: 'DEMO-2026-005',
    title: 'Webhookの送信先チェックを回避して内部サービスへ接続できる',
    product: 'SampleHook Relay',
    affectedVersions: '0.9.0以上、1.3.2未満',
    fixedVersion: '1.3.2',
    severity: 'high',
    cvss: 8.2,
    publishedAt: '2026-09-23T06:40:00.000Z',
    updatedAt: '2026-09-23T08:00:00.000Z',
    summary: 'Webhook送信機能で、URLのリダイレクト先を検証しない問題です。外部の送信先URLを登録できる利用者から、内部ネットワークへ接続される可能性があります。',
    exploitation: 'not-observed',
    affectedComponent: 'samplehook-relay / outbound request',
    remediation: ['修正版1.3.2へ更新する。', '名前解決後の接続先とリダイレクト先の両方を検証する。', '送信元のネットワーク権限を制限する。'],
    analysis: {
      summary: 'クライアントライブラリの存在だけでは、影響する送信処理を利用しているか断定できません。',
      evidence: 'samplehook-clientとrelay本体は別のパッケージです。同じ送信処理を利用するかは未確認です。',
      confidence: 'low',
    },
    relevance: { kind: 'review', reason: '関連するクライアントは存在しますが、影響するサーバー実装の使用は未確認です。', score: 33, priority: 'review', packageName: 'samplehook-client', installedVersion: '1.2.0' },
    sources: reference(918, 'サーバーサイドリクエストフォージェリ'),
  },
  {
    id: 'demo-006',
    advisoryId: 'DEMO-2026-006',
    title: 'Markdownプレビューのリンク処理でスクリプトが実行される',
    product: 'DemoMarkdown',
    affectedVersions: '2.0.0以上、2.7.1未満',
    fixedVersion: '2.7.1',
    severity: 'medium',
    cvss: 6.1,
    publishedAt: '2026-09-22T23:30:00.000Z',
    updatedAt: '2026-09-23T01:00:00.000Z',
    summary: 'Markdownレンダラーが、リンク先のURLスキームを制限していません。他人が投稿した内容をプレビューする際に、スクリプトが実行される可能性があります。',
    exploitation: 'poc',
    affectedComponent: 'demo-markdown / link renderer',
    remediation: ['修正版2.7.1へ更新する。', '出力HTMLを用途に合う設定でサニタイズする。', 'リンクに利用できるURLスキームを制限する。'],
    analysis: {
      summary: '表示時のサニタイズ処理と、信頼できない投稿を表示する画面の有無を確認します。',
      evidence: '2.6.0のリンク処理はURLスキームを制限していません。アプリ側のサニタイズによる緩和の有無は未確認です。',
      confidence: 'medium',
    },
    relevance: { kind: 'direct', reason: 'Markdown表示ライブラリが影響範囲に含まれます。', score: 86, priority: 'high', packageName: 'demo-markdown', installedVersion: '2.6.0' },
    sources: reference(79, 'クロスサイトスクリプティング'),
  },
  {
    id: 'demo-007',
    advisoryId: 'DEMO-2026-007',
    title: 'プロジェクトIDの変更で別組織の監査レポートを参照できる',
    product: 'TrialAudit Portal',
    affectedVersions: '5.1.0以上、5.3.0未満',
    fixedVersion: '5.3.0',
    severity: 'high',
    cvss: 7.5,
    publishedAt: '2026-09-22T08:20:00.000Z',
    updatedAt: '2026-09-22T09:40:00.000Z',
    summary: '監査ポータルで、レポート取得時に組織への所属を確認しない問題です。認証済みであっても、対象レポートを閲覧できる権限の確認が必要になります。',
    exploitation: 'not-observed',
    affectedComponent: 'trialaudit-portal / report API',
    remediation: ['修正版5.3.0へ更新する。', 'リソース取得ごとに組織と利用者の権限を検証する。', '他組織のリソースへのアクセスを拒否するテストを追加する。'],
    analysis: {
      summary: '認証の有無と、特定リソースへの閲覧権限を分けて確認します。',
      evidence: 'レポートIDの受け取り後に、取得対象の組織と利用者の所属を照合する処理が不足しています。',
      confidence: 'medium',
    },
    sources: reference(639, '利用者が制御するキーによる認可の回避'),
  },
  {
    id: 'demo-008',
    advisoryId: 'DEMO-2026-008',
    title: '入れ子の深いデータを受信するとパーサーが大量のCPUを消費する',
    product: 'ExampleData Parser',
    affectedVersions: '1.2.0以上、1.9.2未満',
    fixedVersion: '1.9.2',
    severity: 'medium',
    cvss: 5.3,
    publishedAt: '2026-09-22T02:00:00.000Z',
    updatedAt: '2026-09-22T04:00:00.000Z',
    summary: 'データパーサーが、入れ子の深さに応じて過剰な処理を行います。入力サイズの上限だけでは、処理時間の増加を防げない場合があります。',
    exploitation: 'not-observed',
    affectedComponent: 'exampledata-parser / recursive decoder',
    remediation: ['修正版1.9.2へ更新する。', '入力サイズと入れ子の深さに上限を設ける。', '処理時間を制限し、過負荷時の挙動を確認する。'],
    analysis: {
      summary: '影響バージョンのパーサーへ外部入力を渡す構成が対象です。入力を受け取る経路の有無を確認してください。',
      evidence: '1.8.3の再帰デコード処理に深さの上限がありません。外部入力がその処理へ到達するかは未確認です。',
      confidence: 'medium',
    },
    relevance: { kind: 'transitive', reason: '利用中のSDK経由の依存です。外部入力を処理する箇所を確認してください。', score: 68, priority: 'medium', packageName: 'exampledata-parser', installedVersion: '1.8.3' },
    sources: reference(400, '制御されていないリソース消費'),
  },
  {
    id: 'demo-009',
    advisoryId: 'DEMO-2026-009',
    title: '署名アルゴリズムの選択不備によりセッショントークンを偽装できる',
    product: 'SampleSession',
    affectedVersions: '3.1.0以上、3.2.5未満',
    fixedVersion: '3.2.5',
    severity: 'critical',
    cvss: 9.1,
    publishedAt: '2026-09-21T10:00:00.000Z',
    updatedAt: '2026-09-21T12:00:00.000Z',
    summary: 'セッション管理で、信頼できないトークンの指定に従って検証方式を選ぶ問題です。一部の設定では、必要な署名検証を行わずに認証する可能性があります。',
    exploitation: 'observed',
    affectedComponent: 'sample-session / token verifier',
    remediation: ['修正版3.2.5へ更新する。', '許可する署名アルゴリズムをサーバー側で固定する。', '影響を受けた可能性のあるセッションを失効し、認証ログを確認する。'],
    analysis: {
      summary: '検証方式の設定が条件です。製品名やバージョンだけで認証回避が成立すると断定しません。',
      evidence: 'トークンのヘッダーから検証方式を選択しています。サーバー側で許可するアルゴリズムを固定しているかが確認点です。',
      confidence: 'medium',
    },
    sources: reference(347, '暗号署名の不適切な検証'),
  },
  {
    id: 'demo-010',
    advisoryId: 'DEMO-2026-010',
    title: '診断ログにアクセストークンの一部が記録される',
    product: 'DemoTrace Collector',
    affectedVersions: '0.8.0以上、1.1.4未満',
    fixedVersion: '1.1.4',
    severity: 'low',
    cvss: 3.3,
    publishedAt: '2026-09-21T04:30:00.000Z',
    updatedAt: '2026-09-21T05:00:00.000Z',
    summary: '診断ログ収集機能で、デバッグ出力にトークンの一部が含まれます。通常運用では無効な診断モードを有効化している場合が確認対象です。',
    exploitation: 'not-observed',
    affectedComponent: 'demotrace-collector / debug logger',
    remediation: ['修正版1.1.4へ更新する。', '不要な診断モードを無効にする。', '既存ログへのアクセス権と保持期間を確認する。'],
    analysis: {
      summary: '診断モードの利用とログの閲覧範囲を確認し、情報の組み合わせによる影響を評価します。',
      evidence: '診断出力にトークンの一部が含まれます。全文の露出は確認されていませんが、ほかのログとの組み合わせに注意が必要です。',
      confidence: 'medium',
    },
    sources: reference(532, 'ログへの機密情報の挿入'),
  },
  {
    id: 'demo-011',
    advisoryId: 'DEMO-2026-011',
    title: 'エクスポート先の認可確認漏れで共有ファイルが上書きされる',
    product: 'TrialExport Worker',
    affectedVersions: '2.0.0以上、2.3.1未満',
    fixedVersion: '2.3.1',
    severity: 'high',
    cvss: 7.1,
    publishedAt: '2026-09-20T07:00:00.000Z',
    updatedAt: '2026-09-20T08:30:00.000Z',
    summary: 'レポート出力機能で、ジョブ登録時の権限を出力先へ適用しない問題です。共有領域にある別ユーザーのファイルを上書きできる可能性があります。',
    exploitation: 'not-observed',
    affectedComponent: 'trialexport-worker / destination resolver',
    remediation: ['修正版2.3.1へ更新する。', 'ジョブ実行時にも出力先への書き込み権限を検証する。', '既存ファイルを意図せず上書きしない設定にする。'],
    analysis: {
      summary: '登録時と実行時の間で権限が変わる場合も含め、実行時の認可を確認します。',
      evidence: 'ジョブの実行時に、出力先への書き込み権限を再確認していません。登録後の権限変更も考慮する必要があります。',
      confidence: 'medium',
    },
    sources: reference(862, '認可処理の欠如'),
  },
  {
    id: 'demo-012',
    advisoryId: 'DEMO-2026-012',
    title: 'エラーページに内部パスと構成情報が表示される',
    product: 'ExampleConfig UI',
    affectedVersions: '1.0.0以上、1.4.2未満',
    fixedVersion: '1.4.2',
    severity: 'unknown',
    cvss: null,
    publishedAt: '2026-09-20T01:15:00.000Z',
    updatedAt: '2026-09-20T03:00:00.000Z',
    summary: '設定画面で、例外の内容をそのままブラウザーへ返す問題です。ファイルの内部パスや設定キーの名称が露出します。スコアは未評価です。',
    exploitation: 'not-observed',
    affectedComponent: 'exampleconfig-ui / error handler',
    remediation: ['修正版1.4.2へ更新する。', '利用者向けのエラーと内部ログを分離する。', '本番環境で詳細なデバッグ表示を無効にする。'],
    analysis: {
      summary: '表示された情報に秘密値が含まれるかは未確認です。追加情報なしに影響を拡大して解釈しません。',
      evidence: '例外メッセージに内部パスと設定キー名が含まれます。秘密値の露出や追加の影響は未確認です。',
      confidence: 'low',
    },
    sources: reference(209, 'エラーメッセージによる情報の露出'),
  },
]

interface RepositoryProfileEntry {
  id: string
  relevance: NonNullable<FeedItem['relevance']>
}

// Deterministic local fixtures, not a scan of the supplied repository.
const repositoryProfiles: RepositoryProfileEntry[][] = [
  [
    { id: 'demo-002', relevance: { kind: 'direct', score: 95, priority: 'urgent', reason: '認証済みAPIの応答キャッシュで利用しています。ユーザー間の応答共有を優先して確認してください。', packageName: 'democache-gateway', installedVersion: '2.5.0' } },
    { id: 'demo-004', relevance: { kind: 'direct', score: 91, priority: 'urgent', reason: '管理APIのログ検索で利用しています。クエリの組み立て箇所を確認してください。', packageName: 'examplelog-search', installedVersion: '4.2.0' } },
    { id: 'demo-005', relevance: { kind: 'direct', score: 83, priority: 'high', reason: 'Webhookの送信処理に使用しています。リダイレクト後の接続先を確認してください。', packageName: 'samplehook-relay', installedVersion: '1.2.0' } },
    { id: 'demo-007', relevance: { kind: 'transitive', score: 75, priority: 'high', reason: '監査レポートの取得経路に含まれます。組織ごとの権限判定を確認してください。', packageName: 'trialaudit-portal', installedVersion: '5.2.0' } },
    { id: 'demo-009', relevance: { kind: 'review', score: 62, priority: 'review', reason: '認証ライブラリは一致しますが、署名アルゴリズムを固定しているかの確認が必要です。', packageName: 'sample-session', installedVersion: '3.2.1' } },
  ],
  [
    { id: 'demo-003', relevance: { kind: 'transitive', score: 71, priority: 'high', reason: 'ファイル変換ツールから間接的に使用しています。出力先の境界を確認してください。', packageName: 'trial-attachment', installedVersion: '1.8.0' } },
    { id: 'demo-008', relevance: { kind: 'direct', score: 97, priority: 'urgent', reason: '外部ファイルのインポート経路で使用しています。入力の深さ制限を優先して確認してください。', packageName: 'exampledata-parser', installedVersion: '1.8.3' } },
    { id: 'demo-010', relevance: { kind: 'direct', score: 65, priority: 'medium', reason: '診断モードが運用設定に含まれます。ログの共有範囲とトークンのマスキングを確認してください。', packageName: 'demotrace-collector', installedVersion: '1.1.0' } },
    { id: 'demo-012', relevance: { kind: 'review', score: 25, priority: 'low', reason: '設定画面は内部向けです。外部公開の有無とエラー出力を確認してください。', packageName: 'exampleconfig-ui', installedVersion: '1.4.0' } },
  ],
]

// Classification belongs to the scoped data, before search and relevance ordering.
const pendingRepositoryIds = new Set(['demo-005', 'demo-009', 'demo-012'])

export function repositoryFeedFor(repositoryLabel: string): FeedItem[] {
  const normalized = repositoryLabel.toLowerCase()
  const profileIndex = [...normalized].reduce((sum, character) => sum + character.codePointAt(0)!, 0) % 3
  const items = profileIndex === 0 ? mockFeed.filter(item => item.relevance !== undefined)
    : repositoryProfiles[profileIndex - 1]!.flatMap(({ id, relevance }) => {
      const item = mockFeed.find(article => article.id === id)
      return item ? [{ ...item, relevance: { ...relevance } }] : []
    })
  return items.map(item => ({
    ...item,
    repositoryAnalysis: pendingRepositoryIds.has(item.id) ? 'pending' : 'analyzed',
    ...(pendingRepositoryIds.has(item.id) && item.relevance
      ? { relevance: { ...item.relevance, priority: 'review' as const, score: undefined } } : {}),
  }))
}
