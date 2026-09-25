import { MAX_URL_LENGTH, isWellFormedText } from '../utils/publicUrl'
import { mockFeed, mockGeneratedAt, repositoryFeedFor } from '../mocks/feed'
import type {
  FeedItem,
  FeedOptions,
  FeedQuery,
  FeedResult,
  RepositoryUrlResult,
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
}

/** Validates input only; this does not establish that a repository is public or exists. */
export function parseRepositoryUrl(input: unknown): RepositoryUrlResult {
  const invalid = (message: string): RepositoryUrlResult => ({ ok: false, message })
  if (typeof input !== 'string' || input.length > MAX_URL_LENGTH || !isWellFormedText(input) || /[\u0000-\u001f\u007f]/u.test(input)) return invalid('2,048文字以内の正しいリポジトリURLを入力してください。')
  const value = input.trim()

  if (!value) return invalid('公開GitHubリポジトリのURLを入力してください。')
  if (/[\s\\%?#]/u.test(value)) {
    return invalid('クエリ・フラグメント・エンコードを含まないリポジトリURLを入力してください。')
  }

  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return invalid('https://github.com/所有者/リポジトリ の形式で入力してください。')
  }

  if (parsed.protocol !== 'https:' || parsed.hostname !== 'github.com') {
    return invalid('現在は https://github.com/ で始まるURLに対応しています。')
  }
  if (parsed.username || parsed.password || parsed.port || /^https:\/\/[^/]*@/iu.test(value)) {
    return invalid('認証情報や独自のポート番号を含まないURLを入力してください。')
  }

  // Validate the original path too: URL() normalizes /./ and /../ before inspection.
  const originalPath = value.match(/^https:\/\/[^/]+(\/.*)$/iu)?.[1]
  const path = originalPath?.match(/^\/([a-z\d](?:[a-z\d-]*[a-z\d])?)\/([a-z\d_.-]+)\/?$/iu)
  if (!path) {
    return invalid('ファイルやブランチではなく、リポジトリのトップページのURLを入力してください。')
  }

  const owner = path[1]!
  const repository = path[2]!.replace(/\.git$/iu, '')
  if (!repository || repository === '.' || repository === '..') {
    return invalid('リポジトリ名を含むURLを入力してください。')
  }

  const label = `${owner}/${repository}`
  return { ok: true, url: `https://github.com/${label.toLowerCase()}`, label }
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

const normalizeSearch = (text: string) => text.normalize('NFKC').toLocaleLowerCase('ja-JP')

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
    if (query.severity !== 'all' && (item.assessment === 'unverified' || item.severity !== query.severity)) return false
    const searchable = normalizeSearch([
      item.advisoryId,
      item.title,
      item.product,
      item.affectedComponent,
      item.summary,
      item.relevance?.packageName ?? '',
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
      const severityDifference = (a.assessment === 'unverified' ? 4 : severityOrder[a.severity]) - (b.assessment === 'unverified' ? 4 : severityOrder[b.severity])
      if (severityDifference) return severityDifference
    }
    return b.publishedAt.localeCompare(a.publishedAt) || a.id.localeCompare(b.id)
  })

  return items
}
