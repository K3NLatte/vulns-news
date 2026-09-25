import { MAX_URL_LENGTH, isWellFormedText, parsePublicHttpsUrl } from '../utils/publicUrl'
import { hasUnsafeCharacters } from '../utils/inputText'
import { isStoredDate } from './reportSession'
import type { FeedItem } from '../types/feed'
import type {
  ReportInputKind,
  ReportInputResult,
  ReportLifecycle,
  ReportOrigin,
  SavedReportReference,
} from '../types/reports'

export type { ReportInputKind, ReportInputResult, ReportLifecycle, ReportOrigin } from '../types/reports'

const DAY_MS = 24 * 60 * 60 * 1_000
export const TRACKING_DAYS = 7
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/iu
const GHSA_PATTERN = /^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/iu

/** Input syntax only. DNS resolution, redirects and fetch restrictions belong to the backend. */
export function normalizeReportInput(raw: unknown): ReportInputResult {
  const invalid = (message: string): ReportInputResult => ({ ok: false, message })
  if (typeof raw !== 'string' || raw.length > MAX_URL_LENGTH || !isWellFormedText(raw)) return invalid('入力は2,048文字以内にしてください。')
  if (hasUnsafeCharacters(raw) || /[\r\n\t\\]/u.test(raw)) return invalid('改行や制御文字を含まないID・URLを入力してください。')
  const value = raw.trim()
  if (!value) return invalid('CVE・GHSAのID、またはアドバイザリのURLを入力してください。')
  const identifier = value.normalize('NFKC')
  if (CVE_PATTERN.test(identifier)) return { ok: true, kind: 'cve', key: identifier.toUpperCase() }
  if (GHSA_PATTERN.test(identifier)) return { ok: true, kind: 'ghsa', key: identifier.toUpperCase() }

  if (/^CVE(?:[-\s]|$)/iu.test(identifier)) return invalid('CVE-年-4桁以上の番号の形式で入力してください。')
  if (/^GHSA(?:[-\s]|$)/iu.test(identifier)) return invalid('GHSA-xxxx-xxxx-xxxx の形式で入力してください。')
  const url = parsePublicHttpsUrl(value)
  if (!url) return invalid('認証情報や独自ポートを含まない、公開アドバイザリのHTTPS URLを入力してください。')
  if ([...url.searchParams.keys()].some(key => /^(?:access[_-]?token|token|api[_-]?key|password|secret|authorization|session)$/iu.test(key))) {
    return invalid('認証情報と思われるクエリが含まれています。token・sessionなどを削除した公開URLを入力してください。')
  }
  url.hash = ''
  return { ok: true, kind: 'url', key: url.href }
}

function advisoryIdFromUrl(value: string): string | undefined {
  let url: URL
  try { url = new URL(value) } catch { return undefined }
  const host = url.hostname
  const candidate = host === 'nvd.nist.gov' && url.pathname.startsWith('/vuln/detail/')
    ? url.pathname.slice('/vuln/detail/'.length)
    : host === 'github.com' && url.pathname.startsWith('/advisories/')
      ? url.pathname.slice('/advisories/'.length)
      : (host === 'www.cve.org' || host === 'cve.org') && url.pathname === '/CVERecord'
        ? url.searchParams.get('id') ?? ''
        : ''
  const id = candidate.replace(/\/$/u, '')
  return CVE_PATTERN.test(id) || GHSA_PATTERN.test(id) ? id.toUpperCase() : undefined
}

function comparisonKey(value: string): string {
  const normalized = normalizeReportInput(value)
  if (!normalized.ok) return value.toUpperCase()
  return normalized.kind === 'url' ? advisoryIdFromUrl(normalized.key) ?? normalized.key : normalized.key
}

export function findExistingReport(inputKey: string, items: FeedItem[]): FeedItem | undefined {
  const key = comparisonKey(inputKey)
  return items.find((item) => [item.id, item.advisoryId, ...item.sources.filter(source => source.kind === 'vendor' || advisoryIdFromUrl(source.url)).map(source => source.url)]
    .some((value) => comparisonKey(value) === key))
}

/** Compact local identifier only; not a secret, authentication token or cryptographic hash. */
function localReportId(value: string): string {
  let first = 0xdeadbeef
  let second = 0x41c6ce57
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    first = Math.imul(first ^ code, 2654435761)
    second = Math.imul(second ^ code, 1597334677)
  }
  first = Math.imul(first ^ (first >>> 16), 2246822507) ^ Math.imul(second ^ (second >>> 13), 3266489909)
  second = Math.imul(second ^ (second >>> 16), 2246822507) ^ Math.imul(first ^ (first >>> 13), 3266489909)
  return `${(first >>> 0).toString(16).padStart(8, '0')}${(second >>> 0).toString(16).padStart(8, '0')}`
}
/** Creates a submission record, not an assertion that the advisory exists or affects any product. */
export function createSubmittedReport(inputKey: string, kind: ReportInputKind, nowISO: string): FeedItem {
  const parsed = normalizeReportInput(inputKey)
  if (!parsed.ok || parsed.kind !== kind) throw new Error('入力を検証してから解析を依頼してください。')
  const now = iso(time(nowISO))
  const key = parsed.key
  const sourceUrl = kind === 'cve' ? `https://nvd.nist.gov/vuln/detail/${key}`
    : kind === 'ghsa' ? `https://github.com/advisories/${key}` : key
  return {
    // Workspace IDs are bounded to 200 characters, including the submitted- prefix.
    id: kind === 'url' || key.length > 190 ? `submitted-${kind}-${localReportId(key)}` : `submitted-${key}`,
    advisoryId: kind === 'url' ? advisoryIdFromUrl(key) ?? `${new URL(key).hostname}${new URL(key).pathname}` : key,
    title: kind === 'url' ? `${new URL(key).hostname} のアドバイザリ` : `${key} の調査`,
    product: null,
    affectedVersions: null,
    fixedVersion: null,
    severity: 'unknown',
    cvss: null,
    assessment: 'unverified',
    publishedAt: null,
    updatedAt: null,
    submittedAt: now,
    summary: '入力された情報の存在、対象製品、影響範囲は未確認です。',
    exploitation: 'unknown',
    affectedComponent: null,
    remediation: [],
    repositoryAnalysis: 'pending',
    analysis: {
      summary: null,
      evidence: null,
      confidence: 'unknown',
    },
    sources: [{ name: kind === 'cve' ? 'NVD' : kind === 'ghsa' ? 'GitHub Advisory Database' : new URL(key).hostname, url: sourceUrl, kind: 'reference' }],
  }
}

function time(value: string): number {
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed)) throw new Error('日時が不正です。')
  return parsed
}

const iso = (value: number): string => new Date(value).toISOString()

function nextCheck(analyzedAt: number, trackingUntil: number): string | null {
  const next = analyzedAt + DAY_MS
  return next < trackingUntil ? iso(next) : null
}

export function createReportLifecycle(item: FeedItem, nowISO: string, origin: ReportOrigin = 'feed'): ReportLifecycle {
  const now = time(nowISO)
  const pending = item.assessment === 'unverified' || item.analysis.confidence === 'unknown' || item.updatedAt === null
  const analyzedAt = pending ? null : time(item.updatedAt!)
  const trackingUntil = (analyzedAt ?? now) + TRACKING_DAYS * DAY_MS
  return {
    articleId: item.id,
    lastAnalyzedAt: analyzedAt === null ? null : iso(analyzedAt),
    trackingUntil: iso(trackingUntil),
    nextCheckAt: analyzedAt === null || now >= trackingUntil ? null : nextCheck(analyzedAt, trackingUntil),
    revision: pending ? 0 : 1,
    history: analyzedAt === null ? [] : [{ revision: 1, analyzedAt: iso(analyzedAt), reason: 'initial' }],
    origin,
  }
}

export function isTrackingActive(lifecycle: ReportLifecycle, nowISO: string): boolean {
  return lifecycle.revision > 0 && time(nowISO) < time(lifecycle.trackingUntil)
}

/** Scheduling never extends tracking. Expired reports are updated only by an explicit manual request. */
export function updateReportLifecycle(
  lifecycle: ReportLifecycle,
  nowISO: string,
  reason: 'scheduled' | 'manual',
): ReportLifecycle {
  const now = time(nowISO)
  const until = lifecycle.revision === 0 ? now + TRACKING_DAYS * DAY_MS : time(lifecycle.trackingUntil)
  const last = lifecycle.lastAnalyzedAt === null ? null : time(lifecycle.lastAnalyzedAt)
  if (last !== null && now < last) return lifecycle
  if (reason === 'scheduled' && (now >= until || !lifecycle.nextCheckAt || now < time(lifecycle.nextCheckAt))) return lifecycle
  const revision = lifecycle.revision + 1
  const analyzedAt = iso(now)
  return {
    ...lifecycle,
    revision,
    trackingUntil: iso(until),
    lastAnalyzedAt: analyzedAt,
    nextCheckAt: nextCheck(now, until),
    history: [...lifecycle.history, { revision, analyzedAt, reason: lifecycle.revision === 0 ? 'initial' : reason }],
  }
}

/** Renewing tracking is a separate user choice and does not imply an analysis completed. */
export function renewReportTracking(lifecycle: ReportLifecycle, nowISO: string): ReportLifecycle {
  if (lifecycle.revision === 0) return lifecycle
  const now = Math.max(time(nowISO), lifecycle.lastAnalyzedAt ? time(lifecycle.lastAnalyzedAt) : 0)
  const until = now + TRACKING_DAYS * DAY_MS
  return { ...lifecycle, trackingUntil: iso(until), nextCheckAt: iso(now + DAY_MS) }
}

/** Fictional historical advisories for the repository-search design scenario. */
export const historicalReports: FeedItem[] = [
  {
    id: 'history-001',
    advisoryId: 'DEMO-2024-013',
    title: '旧バージョンの圧縮処理で展開サイズの上限を回避できる',
    product: 'ExampleArchive',
    affectedVersions: '1.0.0以上、1.5.3未満',
    fixedVersion: '1.5.3',
    severity: 'high',
    cvss: 7.5,
    publishedAt: '2024-03-08T00:00:00.000Z',
    updatedAt: '2024-03-10T09:00:00.000Z',
    summary: '展開サイズの制限を個々のファイルにしか適用しないため、複数ファイルの合計で上限を超える問題です。',
    exploitation: 'not-observed',
    affectedComponent: 'example-archive / archive reader',
    remediation: ['修正版1.5.3へ更新する。', '展開先全体の使用量とファイル数に上限を設ける。'],
    repositoryAnalysis: 'analyzed',
    analysis: {
      summary: '既存の分析では展開処理が影響範囲です。現在の使用箇所と運用条件を確認してください。',
      evidence: '1.5.1の展開処理で合計サイズが制限されていません。',
      confidence: 'medium',
    },
    relevance: { kind: 'transitive', priority: 'high', score: 87, reason: '間接依存1.5.1が影響範囲に含まれます。', packageName: 'example-archive', installedVersion: '1.5.1' },
    sources: [{ name: 'ExampleArchive アドバイザリ', url: 'https://example.org/advisories/demo-2024-013', kind: 'vendor' }],
  },
  {
    id: 'history-002',
    advisoryId: 'DEMO-2023-014',
    title: '旧HTTPクライアントのリダイレクト時の認証情報転送',
    product: 'SampleHTTP',
    affectedVersions: null,
    fixedVersion: null,
    severity: 'unknown',
    cvss: null,
    assessment: 'unverified',
    publishedAt: '2023-11-14T00:00:00.000Z',
    updatedAt: '2023-11-14T00:00:00.000Z',
    summary: '依存関係と製品名が一致する過去の情報が見つかりました。対象バージョンと影響条件は未評価です。',
    exploitation: 'unknown',
    affectedComponent: 'sample-http / redirect handler',
    remediation: [],
    repositoryAnalysis: 'pending',
    analysis: { summary: '未評価', evidence: '既存の分析結果はありません。対象バージョンと影響条件を確認する必要があります。', confidence: 'unknown' },
    relevance: { kind: 'review', priority: 'review', reason: '間接依存の製品名が一致しました。影響範囲は未確認です。', packageName: 'sample-http', installedVersion: '0.8.2' },
    sources: [{ name: 'SampleHTTP アドバイザリ', url: 'https://example.org/advisories/demo-2023-014', kind: 'vendor' }],
  },
]

/** Rehydrate only a validated submission reference, never persisted report prose. */
export function restoreSavedReport(id: string, value: unknown): FeedItem | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const reference = value as Record<string, unknown>
  if (!isStoredDate(reference.createdAt)) return undefined
  const parsed = normalizeReportInput(reference.input)
  if (!parsed.ok || parsed.key !== reference.input) return undefined
  const item = createSubmittedReport(parsed.key, parsed.kind, reference.createdAt)
  return item.id === id ? item : undefined
}

export function getSavedReportItems(references: Record<string, SavedReportReference>): FeedItem[] {
  return Object.entries(references).flatMap(([id, reference]) => {
    const item = restoreSavedReport(id, reference)
    return item ? [item] : []
  })
}
