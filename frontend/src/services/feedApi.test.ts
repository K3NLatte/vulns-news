import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import all from '../../../server/mockdata/cves.json'
import related from '../../../server/mockdata/repository-feed.json'
import completed from '../../../server/mockdata/job-completed.json'
import queued from '../../../server/mockdata/job-queued.json'
import { createFeedApi } from './feedApi'
import { parseFeedItem } from './feedContract'
import type { FeedQuery, FeedResult } from '../types/feed'

const query: FeedQuery = { scope: 'all', search: '', severity: 'all', sort: 'newest' }
const repositoryQuery: FeedQuery = { ...query, scope: 'repository', repositoryUrl: 'https://github.com/Example/Mock-Service' }
const canonicalUrl = 'https://github.com/example/mock-service'
const ids = { repository_id: 'repo-001', job_id: 'job-001' }
const storageKey = 'vulns-news:api-registrations:v1'
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
function mockFetch() {
  const fetch = vi.fn<typeof globalThis.fetch>()
  vi.stubGlobal('fetch', fetch)
  return fetch
}
function seedRegistrations(rows: unknown[] = [{ url: canonicalUrl, ...ids }]) {
  sessionStorage.setItem(storageKey, JSON.stringify({ version: 1, registrations: rows }))
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}
beforeEach(() => {
  const values = new Map<string, string>()
  vi.stubGlobal('sessionStorage', {
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => { values.set(key, value) }),
  })
})
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

describe('server mock API adapter', () => {
  it('fetches all mock articles before applying search and severity filters', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(response(all))
    const result = await createFeedApi().getFeed({ ...query, search: 'ｓａｍｐｌｅｖｉｅｗ', severity: 'critical' })
    expect(fetch.mock.calls[0]![0]).toBe('/api/cves?limit=200')
    expect(result.items.map(item => item.id)).toEqual(['demo-001'])
    expect(result.total).toBe(12)
    expect(result.matchedTotal).toBe(1)
    expect(result.generatedAt).toBe(all.generatedAt)
  })

  it('requires explicit registration before repository reads and never POSTs from a deep link', async () => {
    const fetch = mockFetch()
    const api = createFeedApi()
    expect(api.hasRepository(canonicalUrl)).toBe(false)
    await expect(api.getFeed(repositoryQuery)).rejects.toThrow('登録情報がありません')
    await expect(api.getDetail({ id: 'demo-001', repositoryUrl: canonicalUrl })).rejects.toThrow('登録情報がありません')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('uses returned registration IDs and avoids POST on reads, retries and duplicate registration', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(response(ids, 202))
      .mockResolvedValueOnce(response(completed))
      .mockResolvedValueOnce(response(related))
      .mockResolvedValueOnce(response(related.items[0]))
      .mockResolvedValueOnce(response(completed))
      .mockResolvedValueOnce(response(related))
    const onJob = vi.fn()
    const api = createFeedApi(onJob)
    expect(await api.registerRepository(repositoryQuery.repositoryUrl!)).toEqual({ url: canonicalUrl, ids })
    expect(api.hasRepository(repositoryQuery.repositoryUrl!)).toBe(true)
    await api.registerRepository(canonicalUrl)
    const result = await api.getFeed(repositoryQuery)
    expect(result.items).toHaveLength(6)
    expect(JSON.parse(fetch.mock.calls[0]![1]!.body as string)).toEqual({ url: canonicalUrl })
    expect(fetch.mock.calls[0]![1]!.method).toBe('POST')
    expect(onJob).toHaveBeenCalledWith(canonicalUrl, completed)
    expect(await api.getDetail({ id: 'demo-001', repositoryUrl: canonicalUrl })).toEqual(related.items[0])
    await api.getFeed({ ...repositoryQuery, sort: 'relevance' })
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      '/api/repositories', '/api/jobs/job-001', '/api/repositories/repo-001/feed',
      '/api/repositories/repo-001/feed/demo-001', '/api/jobs/job-001', '/api/repositories/repo-001/feed',
    ])
  })

  it.each([
    { assessment: undefined, analysis: undefined, relevance: false, expected: 'pending' },
    { assessment: undefined, analysis: undefined, relevance: true, expected: 'pending' },
    { assessment: undefined, analysis: 'pending', relevance: false, expected: 'pending' },
    { assessment: undefined, analysis: 'pending', relevance: true, expected: 'pending' },
    { assessment: undefined, analysis: 'analyzed', relevance: false, expected: 'pending' },
    { assessment: undefined, analysis: 'analyzed', relevance: true, expected: 'analyzed' },
    { assessment: 'unverified', analysis: undefined, relevance: false, expected: 'pending' },
    { assessment: 'unverified', analysis: undefined, relevance: true, expected: 'pending' },
    { assessment: 'unverified', analysis: 'pending', relevance: false, expected: 'pending' },
    { assessment: 'unverified', analysis: 'pending', relevance: true, expected: 'pending' },
    { assessment: 'unverified', analysis: 'analyzed', relevance: false, expected: 'pending' },
    { assessment: 'unverified', analysis: 'analyzed', relevance: true, expected: 'pending' },
  ])('aligns repository lists, details and relevance ordering without changing general results: %j', async scenario => {
    seedRegistrations()
    const candidate = parseFeedItem({
      ...related.items[0], assessment: scenario.assessment, repositoryAnalysis: scenario.analysis,
      relevance: scenario.relevance ? { ...related.items[0]!.relevance, score: 100 } : undefined,
    })
    const confirmed = parseFeedItem({
      ...related.items[0], id: 'confirmed', repositoryAnalysis: 'analyzed',
      publishedAt: '2020-01-01T00:00:00.000Z', relevance: { ...related.items[0]!.relevance, score: 1 },
    })
    const page = { ...related, items: [candidate, confirmed], total: 2, matchedTotal: 2 }
    mockFetch().mockResolvedValueOnce(response(completed)).mockResolvedValueOnce(response(page))
      .mockResolvedValueOnce(response(candidate)).mockResolvedValueOnce(response(page))
      .mockResolvedValueOnce(response(candidate))
    const api = createFeedApi()
    const scoped = await api.getFeed({ ...repositoryQuery, sort: 'relevance' })
    const expectedCandidate = { ...candidate, repositoryAnalysis: scenario.expected }
    expect(scoped.items.find(item => item.id === candidate.id)).toEqual(expectedCandidate)
    expect(scoped.items.map(item => item.id)).toEqual(scenario.expected === 'analyzed'
      ? [candidate.id, confirmed.id] : [confirmed.id, candidate.id])
    expect(await api.getDetail({ id: candidate.id, repositoryUrl: canonicalUrl })).toEqual(expectedCandidate)
    const general = await api.getFeed(query)
    expect(general.items.find(item => item.id === candidate.id)).toEqual(candidate)
    expect(await api.getDetail({ id: candidate.id })).toEqual(candidate)
  })

  it('preserves the current Go fixture assessments in repository lists and every detail', async () => {
    seedRegistrations()
    const fetch = mockFetch().mockResolvedValueOnce(response(completed)).mockResolvedValueOnce(response(related))
    for (const item of related.items) fetch.mockResolvedValueOnce(response(item))
    const api = createFeedApi()
    const scoped = await api.getFeed(repositoryQuery)
    expect(scoped.items).toEqual(related.items)
    expect(scoped.items.filter(item => item.repositoryAnalysis === 'analyzed')).toHaveLength(5)
    expect(scoped.items.filter(item => item.repositoryAnalysis === 'pending').map(item => item.id)).toEqual(['demo-005'])
    for (const item of related.items) {
      expect(await api.getDetail({ id: item.id, repositoryUrl: canonicalUrl })).toEqual(item)
    }
  })

  it('normalizes partial repository results before publishing them on a failed job', async () => {
    seedRegistrations()
    const candidate = parseFeedItem({ ...related.items[0], repositoryAnalysis: undefined })
    mockFetch().mockResolvedValueOnce(response({ ...completed, stage: 'failed' }))
      .mockResolvedValueOnce(response({ ...related, items: [candidate], matchedTotal: 1 }))
    const onProgress = vi.fn()
    await expect(createFeedApi().getFeed(repositoryQuery, { onProgress })).rejects.toThrow('処理に失敗')
    expect(onProgress.mock.calls[0]![0].items).toEqual([{ ...candidate, repositoryAnalysis: 'pending' }])
  })
  it('restores validated IDs after creating a new adapter without registering again', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(response(ids, 202))
      .mockResolvedValueOnce(response(completed)).mockResolvedValueOnce(response(related))
    await createFeedApi().registerRepository(canonicalUrl)
    const restored = createFeedApi()
    expect(restored.hasRepository(canonicalUrl)).toBe(true)
    await restored.getFeed(repositoryQuery)
    expect(fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1)
  })

  it.each([
    [{ url: canonicalUrl, ...ids, repository_id: '../secret' }],
    [{ url: 'https://github.com/Example/Mock-Service', ...ids }],
    [{ url: 'https://user:password@github.com/example/mock-service', ...ids }],
    [{ url: 'https://localhost/example/mock-service', ...ids }],
    [{ url: canonicalUrl, ...ids }, { url: canonicalUrl, ...ids }],
  ].map(rows => ({ rows })))('ignores an invalid saved registration without making a request: %j', async ({ rows }) => {
    seedRegistrations(rows)
    const fetch = mockFetch()
    const api = createFeedApi()
    expect(api.hasRepository(canonicalUrl)).toBe(false)
    await expect(api.getFeed(repositoryQuery)).rejects.toThrow('登録情報')
    expect(fetch).not.toHaveBeenCalled()
  })

  it.each(['{broken', '{"version":2,"registrations":[]}', '{"version":1,"registrations":{}}'])('ignores unusable session storage: %s', raw => {
    sessionStorage.setItem(storageKey, raw)
    expect(createFeedApi().hasRepository(canonicalUrl)).toBe(false)
  })

  it('keeps current registrations usable when storage reads and writes throw', async () => {
    vi.stubGlobal('sessionStorage', {
      getItem: () => { throw new Error('storage blocked') },
      setItem: () => { throw new Error('storage blocked') },
    })
    const fetch = mockFetch().mockResolvedValueOnce(response(ids, 202))
      .mockResolvedValueOnce(response(related.items[0]))
    const api = createFeedApi()
    await api.registerRepository(canonicalUrl)
    expect(api.hasRepository(canonicalUrl)).toBe(true)
    expect((await api.getDetail({ id: 'demo-001', repositoryUrl: canonicalUrl })).id).toBe('demo-001')
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('shares concurrent registration while cancelling only the interrupted caller', async () => {
    const result = deferred<Response>()
    const fetch = mockFetch().mockReturnValueOnce(result.promise)
    const api = createFeedApi()
    const controller = new AbortController()
    const first = api.registerRepository(canonicalUrl, controller.signal)
    const rejection = expect(first).rejects.toMatchObject({ name: 'AbortError' })
    const second = api.registerRepository(repositoryQuery.repositoryUrl!)
    controller.abort()
    await rejection
    result.resolve(response(ids, 202))
    expect(await second).toEqual({ url: canonicalUrl, ids })
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(createFeedApi().hasRepository(canonicalUrl)).toBe(true)
  })

  it('stores a response received after the only registration caller was cancelled', async () => {
    const result = deferred<Response>()
    const fetch = mockFetch().mockReturnValueOnce(result.promise)
    const api = createFeedApi()
    const controller = new AbortController()
    const pending = api.registerRepository(canonicalUrl, controller.signal)
    const rejection = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    controller.abort()
    await rejection
    result.resolve(response(ids, 202))
    await api.registerRepository(canonicalUrl)
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(createFeedApi().hasRepository(canonicalUrl)).toBe(true)
  })

  it('handles cancellation during registration dispatch and a later rejected response', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    mockFetch().mockImplementationOnce(() => {
      controller.abort()
      return new Promise<never>(() => {})
    })
    const api = createFeedApi()
    await expect(api.registerRepository(canonicalUrl, controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    await vi.advanceTimersByTimeAsync(15_000)
    expect(api.hasRepository(canonicalUrl)).toBe(false)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('rejects feed IDs that cannot safely identify a detail endpoint', async () => {
    mockFetch().mockResolvedValueOnce(response({
      ...all, items: [{ ...all.items[0], id: '../outside' }], matchedTotal: 1,
    }))
    await expect(createFeedApi().getFeed(query)).rejects.toThrow('データ形式')
  })
  it('does not expose mutable registration objects to callers', async () => {
    mockFetch().mockResolvedValueOnce(response(ids, 202))
    const api = createFeedApi()
    const result = await api.registerRepository(canonicalUrl)
    result.ids.repository_id = 'changed'
    expect((await api.registerRepository(canonicalUrl)).ids).toEqual(ids)
  })

  it('gets a general article from its detail endpoint and rejects a mismatched ID', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(response(all.items[1])).mockResolvedValueOnce(response(all.items[0]))
    const api = createFeedApi()
    expect((await api.getDetail({ id: 'demo-002' })).id).toBe('demo-002')
    expect(fetch.mock.calls[0]![0]).toBe('/api/cves/demo-002')
    await expect(api.getDetail({ id: 'demo-002' })).rejects.toThrow('データ形式')
  })

  it.each([404, 500])('handles a text HTTP %i error without leaking the body', async status => {
    mockFetch().mockResolvedValueOnce(new Response('internal file path', { status }))
    await expect(createFeedApi().getFeed(query)).rejects.toThrow(status === 404 ? '見つかりません' : 'HTTP 500')
  })

  it('does not fall back to local mock data on a network failure', async () => {
    mockFetch().mockRejectedValueOnce(new TypeError('Failed to fetch: internal address'))
    await expect(createFeedApi().getFeed(query)).rejects.toThrow('APIに接続できません')
  })

  it('rejects broken JSON and malformed feed data', async () => {
    mockFetch().mockResolvedValueOnce(new Response('<html>proxy error</html>'))
      .mockResolvedValueOnce(response({ items: [{}], total: 1, matchedTotal: 1, generatedAt: all.generatedAt }))
    const api = createFeedApi()
    await expect(api.getFeed(query)).rejects.toThrow('データ形式')
    await expect(api.getFeed(query)).rejects.toThrow('データ形式')
  })

  it('rejects malformed registration and cross-repository job responses', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(response({ repository_id: '../outside', job_id: 'job-001' }, 202))
      .mockResolvedValueOnce(response(ids, 202))
      .mockResolvedValueOnce(response({ ...completed, repository_id: 'repo-other' }))
    const api = createFeedApi()
    await expect(api.registerRepository(canonicalUrl)).rejects.toThrow('データ形式')
    expect(api.hasRepository(canonicalUrl)).toBe(false)
    await api.registerRepository(canonicalUrl)
    await expect(api.getFeed(repositoryQuery)).rejects.toThrow('データ形式')
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it.each([
    { stage: 'unknown' }, { total: -1 }, { processed: 2, total: 1 },
    { hasAvailableResults: 'yes' }, { job_id: 'job-other' }, { errorMessage: {} },
  ])('rejects malformed or mismatched job values: %j', async change => {
    seedRegistrations()
    mockFetch().mockResolvedValueOnce(response({ ...completed, ...change }))
    const onJob = vi.fn()
    await expect(createFeedApi(onJob).getFeed(repositoryQuery)).rejects.toThrow('データ形式')
    expect(onJob).not.toHaveBeenCalled()
  })

  it.each([
    { scope: 'invalid' }, { severity: 'invalid' }, { sort: 'invalid' },
    { search: null }, { search: '\u0000' }, { search: 'a'.repeat(2049) },
  ])('rejects invalid queries before fetching: %j', async change => {
    const fetch = mockFetch()
    await expect(createFeedApi().getFeed({ ...query, ...change } as FeedQuery)).rejects.toThrow('データ形式')
    expect(fetch).not.toHaveBeenCalled()
  })

  it('rejects invalid detail IDs and repository URLs before requests', async () => {
    const fetch = mockFetch()
    const api = createFeedApi()
    await expect(api.getDetail({ id: '../secret' })).rejects.toThrow('データ形式')
    await expect(api.getDetail({ id: 'demo-001', repositoryUrl: '' })).rejects.toThrow('URL')
    await expect(api.registerRepository('https://user:secret@github.com/example/repo')).rejects.toThrow('認証情報')
    expect(api.hasRepository('https://localhost/example/repo')).toBe(false)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('polls a queued job until completion and exposes server progress', async () => {
    vi.useFakeTimers()
    seedRegistrations()
    mockFetch().mockResolvedValueOnce(response(queued))
      .mockResolvedValueOnce(response(completed)).mockResolvedValueOnce(response(related))
    const onJob = vi.fn()
    const pending = createFeedApi(onJob).getFeed(repositoryQuery)
    await vi.advanceTimersByTimeAsync(1000)
    expect((await pending).items).toHaveLength(6)
    expect(onJob.mock.calls.map(([, job]) => job.stage)).toEqual(['queued', 'completed'])
  })

  it('emits filtered partial results while analyzing and fetches a final feed', async () => {
    vi.useFakeTimers()
    seedRegistrations()
    const partial = { ...related, items: related.items.slice(0, 1), matchedTotal: 1 }
    const fetch = mockFetch().mockResolvedValueOnce(response({ ...completed, stage: 'analyzing' }))
      .mockResolvedValueOnce(response(partial)).mockResolvedValueOnce(response(completed))
      .mockResolvedValueOnce(response(related))
    const onProgress = vi.fn()
    const pending = createFeedApi().getFeed(repositoryQuery, { onProgress })
    await vi.advanceTimersByTimeAsync(0)
    expect(onProgress).toHaveBeenCalledWith(partial)
    await vi.advanceTimersByTimeAsync(1000)
    expect((await pending).items).toHaveLength(6)
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      '/api/jobs/job-001', '/api/repositories/repo-001/feed',
      '/api/jobs/job-001', '/api/repositories/repo-001/feed',
    ])
  })

  it('reads available results on a failed job and sanitizes its server message', async () => {
    seedRegistrations()
    const secret = 'token=secret C:\\private\\server.log'
    mockFetch().mockResolvedValueOnce(response({ ...completed, stage: 'failed', errorMessage: secret }))
      .mockResolvedValueOnce(response(related))
    const onJob = vi.fn()
    let retained: FeedResult | undefined
    await expect(createFeedApi(onJob).getFeed(repositoryQuery, { onProgress: result => { retained = result } })).rejects.toThrow('処理に失敗')
    expect(retained?.items).toHaveLength(6)
    expect(JSON.stringify(onJob.mock.calls)).not.toContain(secret)
    expect(onJob.mock.calls[0]![1].errorMessage).toContain('処理に失敗')
  })

  it('preserves a previously emitted partial result when the next job request fails', async () => {
    vi.useFakeTimers()
    seedRegistrations()
    const fetch = mockFetch().mockResolvedValueOnce(response({ ...completed, stage: 'analyzing' }))
      .mockResolvedValueOnce(response(related)).mockRejectedValueOnce(new Error('network private detail'))
    const onProgress = vi.fn()
    const pending = createFeedApi().getFeed(repositoryQuery, { onProgress })
    const rejection = expect(pending).rejects.toThrow('APIに接続')
    await vi.advanceTimersByTimeAsync(1000)
    await rejection
    expect(onProgress).toHaveBeenCalledTimes(1)
    expect(onProgress.mock.calls[0]![0].items).toHaveLength(6)
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('bounds job polling and resumes the known job on retry without POST', async () => {
    vi.useFakeTimers()
    seedRegistrations()
    const fetch = mockFetch().mockImplementation(() => Promise.resolve(response(queued)))
    const api = createFeedApi()
    const pending = api.getFeed(repositoryQuery)
    const rejection = expect(pending).rejects.toThrow('処理が続いています')
    await vi.advanceTimersByTimeAsync(60_000)
    await rejection
    expect(fetch).toHaveBeenCalledTimes(60)
    fetch.mockResolvedValueOnce(response(completed)).mockResolvedValueOnce(response(related))
    expect((await api.getFeed(repositoryQuery)).items).toHaveLength(6)
    expect(fetch.mock.calls.every(([, options]) => options?.method === 'GET')).toBe(true)
  })

  it.each(['fetch', 'body'])('bounds a stalled %s even if the implementation ignores abort', async stalled => {
    vi.useFakeTimers()
    const forever = new Promise<never>(() => {})
    const fetch = mockFetch()
    if (stalled === 'fetch') fetch.mockReturnValueOnce(forever)
    else {
      const stalledResponse = response(null)
      vi.spyOn(stalledResponse, 'json').mockReturnValueOnce(forever)
      fetch.mockResolvedValueOnce(stalledResponse)
    }
    const pending = createFeedApi().getFeed(query)
    const rejection = expect(pending).rejects.toThrow('時間内に届きません')
    await vi.advanceTimersByTimeAsync(15_000)
    await rejection
    expect(fetch.mock.calls[0]![1]!.signal?.aborted).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each(['fetch', 'body'])('immediately cancels a stalled %s and discards a late result', async stalled => {
    vi.useFakeTimers()
    const fetchResult = deferred<Response>()
    const bodyResult = deferred<unknown>()
    const fetch = mockFetch()
    if (stalled === 'fetch') fetch.mockReturnValueOnce(fetchResult.promise)
    else {
      const stalledResponse = response(null)
      vi.spyOn(stalledResponse, 'json').mockReturnValueOnce(bodyResult.promise)
      fetch.mockResolvedValueOnce(stalledResponse)
    }
    const controller = new AbortController()
    const onProgress = vi.fn()
    const pending = createFeedApi().getFeed(query, { signal: controller.signal, onProgress })
    const rejection = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await vi.advanceTimersByTimeAsync(0)
    controller.abort('private cancellation reason')
    await rejection
    fetchResult.resolve(response(all))
    bodyResult.resolve(all)
    await vi.advanceTimersByTimeAsync(0)
    expect(onProgress).not.toHaveBeenCalled()
    expect(fetch.mock.calls[0]![1]!.signal?.aborted).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('cancels job polling without fetching another state or a feed', async () => {
    vi.useFakeTimers()
    seedRegistrations()
    const fetch = mockFetch().mockResolvedValueOnce(response(queued))
    const controller = new AbortController()
    const pending = createFeedApi().getFeed(repositoryQuery, { signal: controller.signal })
    const rejection = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await vi.advanceTimersByTimeAsync(0)
    controller.abort()
    await rejection
    await vi.advanceTimersByTimeAsync(2000)
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not fetch a partial feed when a progress listener cancels the request', async () => {
    seedRegistrations()
    const fetch = mockFetch().mockResolvedValueOnce(response({ ...completed, stage: 'analyzing' }))
    const controller = new AbortController()
    const onProgress = vi.fn()
    const api = createFeedApi(() => { controller.abort() })
    await expect(api.getFeed(repositoryQuery, { signal: controller.signal, onProgress })).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(onProgress).not.toHaveBeenCalled()
  })

  it('honors cancellation before registration, feed and detail requests', async () => {
    const fetch = mockFetch()
    const controller = new AbortController()
    controller.abort()
    const api = createFeedApi()
    await expect(api.registerRepository(canonicalUrl, controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    await expect(api.getFeed(query, { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' })
    await expect(api.getDetail({ id: 'demo-001' }, controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetch).not.toHaveBeenCalled()
  })
})
