import { filterFeedItems, parseRepositoryUrl } from './feed'
import { parseFeedItem, parseFeedResult } from './feedContract'
import type { AnalysisSnapshot, AnalysisStage } from '../types/analysis'
import type { FeedOptions, FeedQuery, FeedResult } from '../types/feed'

const listLimit = 200
const pollIntervalMs = 1000
const maxJobChecks = 60
const stages: AnalysisStage[] = ['queued', 'profiling', 'matching', 'screening', 'analyzing', 'completed', 'failed']
interface Registration { repository_id: string; job_id: string }
interface Job extends AnalysisSnapshot { job_id: string; repository_id: string }
export interface DetailTarget { id: string; repositoryUrl?: string }

const invalid = (): never => { throw new Error('APIのデータ形式を確認できませんでした。再試行してください。') }
function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : invalid()
}
function id(value: unknown): string {
  return typeof value === 'string' && /^[a-z\d][a-z\d._:-]{0,199}$/iu.test(value) ? value : invalid()
}
function registration(value: unknown): Registration {
  const data = record(value)
  return { repository_id: id(data.repository_id), job_id: id(data.job_id) }
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
  if (data.errorMessage !== undefined) {
    if (typeof data.errorMessage !== 'string') return invalid()
    job.errorMessage = data.errorMessage
  }
  return job
}
function wait(signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted()
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(signal?.reason) }
    const timer = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve() }, pollIntervalMs)
    signal?.addEventListener('abort', abort, { once: true })
  })
}

/** Server mock adapter. Registration IDs belong to this client, not browser workspace IDs. */
export function createFeedApi(onJob?: (repositoryUrl: string, job: AnalysisSnapshot) => void) {
  const registrations = new Map<string, Registration>()

  async function request(path: string, signal?: AbortSignal, body?: unknown): Promise<unknown> {
    signal?.throwIfAborted()
    let response: Response
    try {
      response = await fetch('/api' + path, {
        method: body === undefined ? 'GET' : 'POST', signal,
        headers: body === undefined ? { Accept: 'application/json' } : { Accept: 'application/json', 'Content-Type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      })
    } catch (cause) {
      if (signal?.aborted) throw cause
      throw new Error('APIに接続できませんでした。サーバーの起動を確認して再試行してください。')
    }
    signal?.throwIfAborted()
    if (!response.ok) {
      if (response.status === 404) throw new Error('指定されたデータが見つかりませんでした。')
      throw new Error(`データを取得できませんでした（HTTP ${response.status}）。再試行してください。`)
    }
    let data: unknown
    try { data = await response.json() } catch (cause) {
      if (signal?.aborted) throw cause
      return invalid()
    }
    signal?.throwIfAborted()
    return data
  }

  async function register(input: string, signal?: AbortSignal): Promise<{ url: string; ids: Registration }> {
    const parsed = parseRepositoryUrl(input)
    if (!parsed.ok) throw new Error(parsed.message)
    signal?.throwIfAborted()
    let ids = registrations.get(parsed.url)
    if (!ids) {
      ids = registration(await request('/repositories', signal, { url: parsed.url }))
      signal?.throwIfAborted()
      registrations.set(parsed.url, ids)
    }
    return { url: parsed.url, ids }
  }

  async function getFeed(query: FeedQuery, options: FeedOptions = {}): Promise<FeedResult> {
    const signal = options.signal
    let path = `/cves?limit=${listLimit}`
    if (query.scope === 'repository') {
      const { url, ids } = await register(query.repositoryUrl ?? '', signal)
      for (let attempt = 0; ; attempt++) {
        const job = jobResponse(await request('/jobs/' + encodeURIComponent(ids.job_id), signal))
        if (job.job_id !== ids.job_id || job.repository_id !== ids.repository_id) return invalid()
        signal?.throwIfAborted()
        onJob?.(url, job)
        if (job.stage === 'failed') throw new Error('リポジトリの処理に失敗しました。再試行してください。')
        if (job.stage === 'completed') break
        if (attempt + 1 >= maxJobChecks) throw new Error('処理が続いています。しばらくしてから再試行してください。')
        await wait(signal)
      }
      path = `/repositories/${encodeURIComponent(ids.repository_id)}/feed`
    }
    const result = parseFeedResult(await request(path, signal))
    const items = filterFeedItems(result.items, query)
    return { ...result, items, matchedTotal: items.length }
  }

  async function getDetail(target: DetailTarget, signal?: AbortSignal) {
    const cveId = id(target.id)
    let path = '/cves/' + encodeURIComponent(cveId)
    if (target.repositoryUrl) {
      const { ids } = await register(target.repositoryUrl, signal)
      path = `/repositories/${encodeURIComponent(ids.repository_id)}/feed/${encodeURIComponent(cveId)}`
    }
    const item = parseFeedItem(await request(path, signal))
    if (item.id !== cveId) return invalid()
    return item
  }

  return { getFeed, getDetail }
}
