import { parseRepositoryUrl } from '../utils/repositoryUrl'
export { parseRepositoryUrl } from '../utils/repositoryUrl'
import { mockFeed, mockGeneratedAt, repositoryFeedFor } from '../mocks/feed'
import type {
  FeedItem,
  FeedOptions,
  FeedQuery,
  FeedResult,
  Severity,
} from '../types/feed'

export type {
  Exploitation,
  FeedItem,
  FeedOptions,
  FeedQuery,
  FeedResult,
  FeedScope,
  FeedSort,
  RepositoryUrlResult,
  ReviewPriority,
  Severity,
} from '../types/feed'

const severityOrder: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  none: 4,
  unknown: 5,
}

function abortError(): DOMException {
  return new DOMException('読み込みを中止しました。', 'AbortError')
}

function wait(delayMs: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError())
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      reject(abortError())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, delayMs)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

function relevanceScore(item: FeedItem): number {
  if (item.repositoryAnalysis === 'pending' || item.assessment === 'unverified') return Number.NEGATIVE_INFINITY
  const score = item.relevance?.score
  return score !== undefined && Number.isFinite(score) ? score : Number.NEGATIVE_INFINITY
}

const normalizeSearch = (text: string) => text.normalize('NFKC').replace(/[‐‑‒–—−]/gu, '-').toLocaleLowerCase('ja-JP')

/**
 * UI data boundary. Replace this implementation with the agreed backend API later.
 * No repository is fetched or analyzed. Repository scope selects a deterministic local profile.
 */
export async function getFeed(query: FeedQuery, options: FeedOptions = {}): Promise<FeedResult> {
  if (options.signal?.aborted) throw abortError()
  let repositoryLabel = ''
  if (query.scope === 'repository') {
    const repository = parseRepositoryUrl(query.repositoryUrl ?? '')
    if (!repository.ok) throw new Error(repository.message)
    repositoryLabel = repository.label
  }

  const requestedDelay = options.delayMs ?? 280
  const delayMs = Number.isFinite(requestedDelay) ? Math.max(0, requestedDelay) : 280
  await wait(delayMs, options.signal)
  if (options.signal?.aborted) throw abortError()
  if (options.scenario === 'error') {
    throw new Error('フィードを読み込めませんでした。しばらくしてから再試行してください。')
  }

  const scoped = options.scenario === 'empty'
    ? []
    : query.scope === 'repository' ? repositoryFeedFor(repositoryLabel) : mockFeed
  const items = filterFeedItems(scoped, query)

  return {
    // Each response is independent: view state must never mutate the shared fixtures.
    items: structuredClone(items),
    total: scoped.length,
    matchedTotal: items.length,
    generatedAt: mockGeneratedAt,
  }
}

/** Shared query rules for acquired reports and the existing feed. */
export function filterFeedItems(source: FeedItem[], query: FeedQuery): FeedItem[] {
  const terms = normalizeSearch(query.search).trim().split(/\s+/u).filter(Boolean)
  const filtered = source.filter((item) => {
    if (query.severity !== 'all' && (item.severity !== query.severity)) return false
    const searchable = normalizeSearch([
      item.advisoryId,
      item.title,
      item.product,
      item.affectedComponent,
      item.summary,
      item.relevance?.packageName ?? '',
      ...item.sources.map(source => source.name),
    ].join(' '))
    return terms.every((term) => searchable.includes(term))
  })
  const items = [...filtered].sort((a, b) => {
    if (query.scope === 'repository' && query.sort === 'relevance') {
      const aScore = relevanceScore(a)
      const bScore = relevanceScore(b)
      if (aScore !== bScore) return bScore - aScore
    }
    if (query.sort === 'severity') {
      const severityDifference = severityOrder[a.severity] - severityOrder[b.severity]
      if (severityDifference) return severityDifference
      const scoreDifference = (b.cvss ?? -1) - (a.cvss ?? -1)
      if (scoreDifference) return scoreDifference
    }
    return (b.publishedAt ?? '').localeCompare(a.publishedAt ?? '') || a.id.localeCompare(b.id)
  })

  return items
}
