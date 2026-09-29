import type { FeedItem, FeedOptions, FeedQuery, FeedResult } from '../types/feed'
import { isWellFormedText } from '../utils/publicUrl'

/** The UI view model, not the Go API's wire format. Adapters map their response before returning it. */
export type FeedLoader = (query: FeedQuery, options: FeedOptions) => Promise<unknown>
const invalid = (): never => { throw new Error('フィードのデータ形式を確認できませんでした。再試行してください。') }
const record = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : invalid()

function text(value: unknown, max = 20_000): string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && isWellFormedText(value)
    && !/[\u0000-\u0008\u000b-\u001f\u007f]/u.test(value) ? value : invalid()
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
export function parseFeedItem(value: unknown): FeedItem {
  const item = record(value)
  const analysis = record(item.analysis)
  const id = text(item.id, 200)
  if (/\s/u.test(id)) return invalid()
  const result: FeedItem = {
    id, advisoryId: text(item.advisoryId, 2048), title: text(item.title),
    product: text(item.product), affectedVersions: text(item.affectedVersions), fixedVersion: text(item.fixedVersion),
    severity: choice(item.severity, ['critical', 'high', 'medium', 'low']),
    cvss: item.cvss === null ? null : number(item.cvss, 0, 10),
    publishedAt: date(item.publishedAt), updatedAt: date(item.updatedAt),
    summary: text(item.summary), exploitation: choice(item.exploitation, ['observed', 'poc', 'not-observed']),
    affectedComponent: text(item.affectedComponent),
    remediation: list(item.remediation, 100, value => text(value)),
    analysis: { summary: text(analysis.summary), evidence: text(analysis.evidence), confidence: choice(analysis.confidence, ['high', 'medium', 'low']) },
    sources: list(item.sources, 100, value => {
      const source = record(value)
      return { name: text(source.name), url: text(source.url, 2048), kind: choice(source.kind, ['vendor', 'reference']) }
    }),
  }
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
  return result
}

/** Reject a malformed page before sorting or rendering, rather than guessing missing facts. */
export function parseFeedResult(value: unknown): FeedResult {
  const data = record(value)
  const items = list(data.items, 1000, parseFeedItem)
  const total = count(data.total)
  const matchedTotal = count(data.matchedTotal)
  if (new Set(items.map(item => item.id)).size !== items.length || matchedTotal !== items.length || total < matchedTotal) return invalid()
  return { items, total, matchedTotal, generatedAt: date(data.generatedAt) }
}
