import { filterFeedItems, parseRepositoryUrl } from './feed'
import { parseFeedItem, parseFeedResult } from './feedContract'
import { canReviewRepositoryArticle } from './repositoryAssessment'
import { isWellFormedText } from '../utils/publicUrl'
import type { AnalysisSnapshot, AnalysisStage } from '../types/analysis'
import type { FeedItem, FeedOptions, FeedQuery, FeedResult } from '../types/feed'

const listLimit = 200
const pollIntervalMs = 1000
const maxJobChecks = 60
const requestTimeoutMs = 15_000
const storageKey = 'vulns-news:api-registrations:v1'
const maxRegistrations = 200
const failedMessage = 'リポジトリの処理に失敗しました。取得済みの結果を確認し、再試行してください。'
const stages: AnalysisStage[] = ['queued', 'profiling', 'matching', 'screening', 'analyzing', 'completed', 'failed']
interface Registration { repository_id: string; job_id: string }
interface RegisteredRepository { url: string; ids: Registration }
interface Job extends AnalysisSnapshot { job_id: string; repository_id: string }
export interface DetailTarget { id: string; repositoryUrl?: string }

const invalid = (): never => { throw new Error('APIのデータ形式を確認できませんでした。再試行してください。') }
const abortError = () => new DOMException('読み込みを中止しました。', 'AbortError')
function checkAbort(signal?: AbortSignal): void { if (signal?.aborted) throw abortError() }
function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : invalid()
}
function id(value: unknown): string {
  return typeof value === 'string' && /^[a-z\d][a-z\d._:-]{0,199}$/iu.test(value) ? value : invalid()
}
function repositoryUrl(value: unknown): string {
  const parsed = parseRepositoryUrl(value)
  if (!parsed.ok) throw new Error(parsed.message)
  return parsed.url
}
function registration(value: unknown): Registration {
  const data = record(value)
  return { repository_id: id(data.repository_id), job_id: id(data.job_id) }
}
function feedQuery(value: unknown): FeedQuery {
  const data = record(value)
  if (!['all', 'repository'].includes(data.scope as string)
    || !['all', 'critical', 'high', 'medium', 'low'].includes(data.severity as string)
    || !['newest', 'severity', 'relevance'].includes(data.sort as string)
    || typeof data.search !== 'string' || data.search.length > 2048 || !isWellFormedText(data.search)
    || /[\u0000-\u001f\u007f]/u.test(data.search)) return invalid()
  return {
    scope: data.scope as FeedQuery['scope'], severity: data.severity as FeedQuery['severity'],
    sort: data.sort as FeedQuery['sort'], search: data.search,
    ...(data.scope === 'repository' ? { repositoryUrl: repositoryUrl(data.repositoryUrl) } : {}),
  }
}
function repositoryItem(item: FeedItem): FeedItem {
  // 一覧・詳細・関連度順で、判断に必要な分析が揃っていない記事を未確定に統一する。
  return canReviewRepositoryArticle(item) ? item : { ...item, repositoryAnalysis: 'pending' }
}
function jobResponse(value: unknown): Job {
  const data = record(value)
  if (!stages.includes(data.stage as AnalysisStage)) return invalid()
  const job: Job = { ...registration(data), stage: data.stage as AnalysisStage }
  for (const key of ['processed', 'total', 'confirmedCount', 'pendingCount'] as const) {
    const value = data[key]
    if (value !== undefined) {
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return invalid()
      job[key] = value
    }
  }
  if (job.processed !== undefined && job.total !== undefined && job.processed > job.total) return invalid()
  if (data.hasAvailableResults !== undefined) {
    if (typeof data.hasAvailableResults !== 'boolean') return invalid()
    job.hasAvailableResults = data.hasAvailableResults
  }
  if (data.errorMessage !== undefined && typeof data.errorMessage !== 'string') return invalid()
  // サーバー内部のパスや診断情報は画面へ渡さない。
  if (job.stage === 'failed') job.errorMessage = failedMessage
  return job
}
function restoreRegistrations(): Map<string, Registration> {
  try {
    const raw = globalThis.sessionStorage?.getItem(storageKey)
    if (!raw || raw.length > 600_000) return new Map()
    const data = record(JSON.parse(raw))
    if (data.version !== 1 || !Array.isArray(data.registrations) || data.registrations.length > maxRegistrations) return new Map()
    const entries = data.registrations.map(value => {
      const row = record(value)
      const url = repositoryUrl(row.url)
      if (url !== row.url) return invalid()
      return [url, registration(row)] as const
    })
    if (new Set(entries.map(([url]) => url)).size !== entries.length) return new Map()
    return new Map(entries)
  } catch { return new Map() }
}
function persistRegistrations(registrations: Map<string, Registration>): void {
  try {
    globalThis.sessionStorage?.setItem(storageKey, JSON.stringify({
      version: 1,
      registrations: Array.from(registrations, ([url, ids]) => ({ url, ...ids })).slice(-maxRegistrations),
    }))
  } catch { /* ストレージを利用できなくても現在の画面では登録結果を保持する。 */ }
}
function wait(signal?: AbortSignal): Promise<void> {
  checkAbort(signal)
  return new Promise((resolve, reject) => {
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort) }
    const abort = () => { cleanup(); reject(abortError()) }
    const timer = setTimeout(() => { cleanup(); resolve() }, pollIntervalMs)
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
  })
}

/** 呼び出し元の中止は、他の画面と共有している登録処理を取り消さない。 */
async function awaitRegistration(pending: Promise<Registration>, signal?: AbortSignal): Promise<Registration> {
  checkAbort(signal)
  if (!signal) return pending
  let onAbort: () => void = () => {}
  const interrupted = new Promise<never>((_, reject) => {
    onAbort = () => reject(abortError())
    signal.addEventListener('abort', onAbort, { once: true })
    if (signal.aborted) onAbort()
  })
  try {
    const result = await Promise.race([pending, interrupted])
    checkAbort(signal)
    return result
  } finally { signal.removeEventListener('abort', onAbort) }
}

/** 登録操作と読み取りを分離し、サーバーが返したIDだけをAPIに渡す。 */
export function createFeedApi(onJob?: (repositoryUrl: string, job: AnalysisSnapshot) => void) {
  const registrations = restoreRegistrations()
  const pendingRegistrations = new Map<string, Promise<Registration>>()

  async function request(path: string, signal?: AbortSignal, body?: unknown): Promise<unknown> {
    checkAbort(signal)
    const controller = new AbortController()
    let onAbort: () => void = () => {}
    let timer: ReturnType<typeof setTimeout> | undefined
    const interrupted = new Promise<never>((_, reject) => {
      onAbort = () => { reject(abortError()); controller.abort() }
      signal?.addEventListener('abort', onAbort, { once: true })
      timer = setTimeout(() => {
        reject(new Error('APIの応答が時間内に届きませんでした。再試行してください。'))
        controller.abort()
      }, requestTimeoutMs)
      if (signal?.aborted) onAbort()
    })
    const operation = async () => {
      checkAbort(signal)
      let response: Response
      try {
        response = await fetch('/api' + path, {
          method: body === undefined ? 'GET' : 'POST', signal: controller.signal,
          headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        })
      } catch {
        checkAbort(signal)
        throw new Error('APIに接続できませんでした。サーバーの起動を確認して再試行してください。')
      }
      checkAbort(signal)
      if (!response.ok) {
        if (response.status === 404) throw new Error('指定されたデータが見つかりませんでした。')
        throw new Error(`データを取得できませんでした（HTTP ${response.status}）。再試行してください。`)
      }
      try { return await response.json() as unknown } catch {
        checkAbort(signal)
        return invalid()
      }
    }
    try {
      // fetchだけでなく本文の読み取りも制限し、中止を無視する実装にも備える。
      const data = await Promise.race([operation(), interrupted])
      checkAbort(signal)
      return data
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
    }
  }

  async function registerRepository(input: string, signal?: AbortSignal): Promise<RegisteredRepository> {
    checkAbort(signal)
    const url = repositoryUrl(input)
    const known = registrations.get(url)
    if (known) return { url, ids: { ...known } }
    let pending = pendingRegistrations.get(url)
    if (!pending) {
      // 中止後も受理済みのIDを保存し、次の読み取りで同じPOSTを繰り返さない。
      pending = request('/repositories', undefined, { url }).then(value => {
        const ids = registration(value)
        registrations.set(url, ids)
        persistRegistrations(registrations)
        return ids
      }).finally(() => { pendingRegistrations.delete(url) })
      pendingRegistrations.set(url, pending)
      // 全呼び出し元が中止済みでも、後から届く失敗を未処理にしない。
      void pending.catch(() => {})
    }
    const ids = await awaitRegistration(pending, signal)
    return { url, ids: { ...ids } }
  }

  function knownRepository(input: unknown): RegisteredRepository {
    const url = repositoryUrl(input)
    const ids = registrations.get(url)
    if (!ids) throw new Error('このリポジトリのAPI登録情報がありません。登録操作から追加してください。')
    return { url, ids: { ...ids } }
  }

  function hasRepository(input: string): boolean {
    const parsed = parseRepositoryUrl(input)
    return parsed.ok && registrations.has(parsed.url)
  }

  async function getFeed(input: FeedQuery, options: FeedOptions = {}): Promise<FeedResult> {
    const signal = options.signal
    checkAbort(signal)
    const query = feedQuery(input)
    if (options.onProgress !== undefined && typeof options.onProgress !== 'function') return invalid()
    const readFeed = async (path: string): Promise<FeedResult> => {
      const result = parseFeedResult(await request(path, signal))
      result.items.forEach(item => { id(item.id) })
      const scopedItems = query.scope === 'repository' ? result.items.map(repositoryItem) : result.items
      const items = filterFeedItems(scopedItems, query)
      return { ...result, items, matchedTotal: items.length }
    }
    if (query.scope === 'all') return readFeed(`/cves?limit=${listLimit}`)

    const { url, ids } = knownRepository(query.repositoryUrl)
    const path = `/repositories/${encodeURIComponent(ids.repository_id)}/feed`
    for (let attempt = 0; attempt < maxJobChecks; attempt++) {
      const job = jobResponse(await request('/jobs/' + encodeURIComponent(ids.job_id), signal))
      if (job.job_id !== ids.job_id || job.repository_id !== ids.repository_id) return invalid()
      checkAbort(signal)
      onJob?.(url, job)
      checkAbort(signal)
      if (job.stage === 'completed') return readFeed(path)
      if (job.hasAvailableResults) {
        const partial = await readFeed(path)
        checkAbort(signal)
        options.onProgress?.(partial)
        checkAbort(signal)
      }
      if (job.stage === 'failed') throw new Error(failedMessage)
      if (attempt + 1 < maxJobChecks) await wait(signal)
    }
    throw new Error('処理が続いています。しばらくしてから再試行してください。')
  }

  async function getDetail(target: DetailTarget, signal?: AbortSignal) {
    checkAbort(signal)
    const data = record(target)
    const cveId = id(data.id)
    let path = '/cves/' + encodeURIComponent(cveId)
    if (data.repositoryUrl !== undefined) {
      const { ids } = knownRepository(data.repositoryUrl)
      path = `/repositories/${encodeURIComponent(ids.repository_id)}/feed/${encodeURIComponent(cveId)}`
    }
    const item = parseFeedItem(await request(path, signal))
    if (item.id !== cveId) return invalid()
    return data.repositoryUrl === undefined ? item : repositoryItem(item)
  }

  return { registerRepository, hasRepository, getFeed, getDetail }
}
