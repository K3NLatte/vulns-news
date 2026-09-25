import type { FeedItem, FeedOptions, FeedQuery, FeedResult } from '../types/feed'
import { isWellFormedText, parsePublicHttpsUrl } from '../utils/publicUrl'
import { hasUnsafeCharacters } from '../utils/inputText'

/** The UI view model, not the Go API's wire format. Adapters map their response before returning it. */
export type FeedLoader = (query: FeedQuery, options: FeedOptions) => Promise<unknown>
const invalid = (): never => { throw new Error('フィードのデータ形式を確認できませんでした。再試行してください。') }
const record = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : invalid()

function text(value: unknown, max = 20_000): string {
  if (typeof value !== 'string' || value.length > max || !isWellFormedText(value)) return invalid()
  const normalized = value.replace(/\r\n?/gu, '\n')
  return normalized.trim().length > 0 && !hasUnsafeCharacters(normalized) ? normalized : invalid()
}
function nullableText(value: unknown): string | null {
  return value === null ? null : text(value)
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  return typeof value === 'string' && choices.includes(value as T) ? value as T : invalid()
}
function number(value: unknown, min: number, max: number): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max ? value : invalid()
}
function count(value: unknown): number {
  const result = number(value, 0, Number.MAX_SAFE_INTEGER)
  return Number.isInteger(result) ? result : invalid()
}
function date(value: unknown): string {
  const candidate = text(value, 24)
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(candidate)
    || !Number.isFinite(Date.parse(candidate)) || new Date(candidate).toISOString() !== candidate) return invalid()
  return candidate
}
function list<T>(value: unknown, max: number, parse: (item: unknown) => T): T[] {
  return Array.isArray(value) && value.length <= max ? value.map(parse) : invalid()
}
function parseItem(value: unknown, trustedVendorHosts: ReadonlySet<string>): FeedItem {
  const item = record(value)
  const analysis = record(item.analysis)
  const id = text(item.id, 200)
  if (!/^[a-z\d][a-z\d._:-]*$/iu.test(id)) return invalid()
  const result: FeedItem = {
    id, advisoryId: text(item.advisoryId, 2048), title: text(item.title),
    product: nullableText(item.product), affectedVersions: nullableText(item.affectedVersions), fixedVersion: nullableText(item.fixedVersion),
    severity: choice(item.severity, ['critical', 'high', 'medium', 'low', 'none', 'unknown']),
    cvss: item.cvss === null ? null : number(item.cvss, 0, 10),
    publishedAt: item.publishedAt === null ? null : date(item.publishedAt),
    updatedAt: item.updatedAt === null ? null : date(item.updatedAt),
    summary: text(item.summary), exploitation: choice(item.exploitation, ['observed', 'poc', 'not-observed', 'unknown']),
    affectedComponent: nullableText(item.affectedComponent),
    remediation: list(item.remediation, 100, value => text(value)),
    analysis: { summary: nullableText(analysis.summary), evidence: nullableText(analysis.evidence), confidence: choice(analysis.confidence, ['high', 'medium', 'low', 'unknown']) },
    sources: list(item.sources, 100, value => {
      const source = record(value)
      const url = parsePublicHttpsUrl(source.url)
      if (!url) return invalid()
      const claimedKind = choice(source.kind, ['vendor', 'reference'])
      return { name: text(source.name), url: url.href, kind: claimedKind === 'vendor' && trustedVendorHosts.has(url.hostname) ? 'vendor' : 'reference' }
    }),
  }
  const expectedSeverity = result.cvss === null ? 'unknown' : result.cvss === 0 ? 'none'
    : result.cvss < 4 ? 'low' : result.cvss < 7 ? 'medium' : result.cvss < 9 ? 'high' : 'critical'
  if (/[\r\n\t]/u.test(result.advisoryId)) return invalid()
  if (result.severity !== expectedSeverity) return invalid()
  if (item.submittedAt !== undefined) result.submittedAt = date(item.submittedAt)
  if (result.publishedAt && result.updatedAt && result.updatedAt < result.publishedAt) return invalid()
  if (item.assessment !== undefined) result.assessment = choice(item.assessment, ['unverified'] as const)
  if (item.repositoryAnalysis !== undefined) result.repositoryAnalysis = choice(item.repositoryAnalysis, ['analyzed', 'pending'] as const)
  if (item.relevance !== undefined) {
    const relevance = record(item.relevance)
    result.relevance = {
      kind: choice(relevance.kind, ['direct', 'transitive', 'review']),
      priority: choice(relevance.priority, ['urgent', 'high', 'medium', 'low', 'review']),
      reason: text(relevance.reason), packageName: text(relevance.packageName), installedVersion: text(relevance.installedVersion),
      ...(relevance.score === undefined ? {} : { score: number(relevance.score, 0, 100) }),
    }
  }
  if (item.proofOfConcept !== undefined) {
    const proof = record(item.proofOfConcept)
    result.proofOfConcept = { language: text(proof.language, 100), code: text(proof.code, 100_000), conditions: list(proof.conditions, 100, value => text(value)) }
  }
  if (result.assessment === 'unverified' && (result.cvss !== null || result.analysis.confidence !== 'unknown' || result.proofOfConcept || result.remediation.length > 0)) return invalid()
  if ((result.repositoryAnalysis === 'pending' || result.assessment === 'unverified') && result.relevance && (result.relevance.score !== undefined || result.relevance.priority !== 'review')) return invalid()
  return result
}

/** Reject invalid envelopes, but quarantine damaged rows so valid reports remain readable. */
export function parseFeedResult(value: unknown, trustedVendorHosts: ReadonlySet<string> = new Set()): FeedResult {
  const data = record(value)
  if (!Array.isArray(data.items) || data.items.length > 1000) return invalid()
  // Bound the complete decoded response as well as individual fields.
  try { if (JSON.stringify(value).length > 2_000_000) return invalid() } catch { return invalid() }
  const total = count(data.total)
  const matchedTotal = count(data.matchedTotal)
  if (total < matchedTotal || matchedTotal < data.items.length) return invalid()
  const ids = new Set<string>()
  const items: FeedItem[] = []
  let rejectedCount = data.rejectedCount === undefined ? 0 : count(data.rejectedCount)
  for (const raw of data.items) {
    try {
      const item = parseItem(raw, trustedVendorHosts)
      if (ids.has(item.id)) { rejectedCount += 1; continue }
      ids.add(item.id)
      items.push(item)
    } catch { rejectedCount += 1 }
  }
  const nextCursor = data.nextCursor === undefined ? undefined
    : data.nextCursor === null ? null : text(data.nextCursor, 2048)
  return {
    items, total, matchedTotal, generatedAt: date(data.generatedAt),
    ...(nextCursor === undefined ? {} : { nextCursor }),
    ...(rejectedCount ? { rejectedCount } : {}),
  }
}
