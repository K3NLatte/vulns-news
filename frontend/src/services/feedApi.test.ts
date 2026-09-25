import { afterEach, describe, expect, it, vi } from 'vitest'
import all from '../../../server/mockdata/cves.json'
import related from '../../../server/mockdata/repository-feed.json'
import completed from '../../../server/mockdata/job-completed.json'
import queued from '../../../server/mockdata/job-queued.json'
import { createFeedApi } from './feedApi'
import type { FeedQuery } from '../types/feed'

const query: FeedQuery = { scope: 'all', search: '', severity: 'all', sort: 'newest' }
const repositoryQuery: FeedQuery = { ...query, scope: 'repository', repositoryUrl: 'https://github.com/Example/Mock-Service' }
const ids = { repository_id: 'repo-001', job_id: 'job-001' }
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status })
function mockFetch() {
  const fetch = vi.fn<typeof globalThis.fetch>()
  vi.stubGlobal('fetch', fetch)
  return fetch
}
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

  it('uses returned registration IDs for jobs, feeds and details, and avoids registering on every filter change', async () => {
    const fetch = mockFetch()
      .mockResolvedValueOnce(response(ids, 202))
      .mockResolvedValueOnce(response(completed))
      .mockResolvedValueOnce(response(related))
      .mockResolvedValueOnce(response(related.items[0]))
      .mockResolvedValueOnce(response(completed))
      .mockResolvedValueOnce(response(related))
    const onJob = vi.fn()
    const api = createFeedApi(onJob)
    const result = await api.getFeed(repositoryQuery)
    expect(result.items).toHaveLength(6)
    expect(JSON.parse(fetch.mock.calls[0]![1]!.body as string)).toEqual({ url: 'https://github.com/example/mock-service' })
    expect(fetch.mock.calls[0]![1]!.method).toBe('POST')
    expect(onJob).toHaveBeenCalledWith('https://github.com/example/mock-service', completed)
    const detail = await api.getDetail({ id: 'demo-001', repositoryUrl: repositoryQuery.repositoryUrl })
    expect(detail).toEqual(related.items[0])
    await api.getFeed({ ...repositoryQuery, sort: 'relevance' })
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([
      '/api/repositories', '/api/jobs/job-001', '/api/repositories/repo-001/feed',
      '/api/repositories/repo-001/feed/demo-001', '/api/jobs/job-001', '/api/repositories/repo-001/feed',
    ])
  })

  it('gets a general article from its detail endpoint and rejects a mismatched ID', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(response(all.items[1])).mockResolvedValueOnce(response(all.items[0]))
    const api = createFeedApi()
    expect((await api.getDetail({ id: 'demo-002' })).id).toBe('demo-002')
    expect(fetch.mock.calls[0]![0]).toBe('/api/cves/demo-002')
    await expect(api.getDetail({ id: 'demo-002' })).rejects.toThrow('データ形式')
  })

  it.each([404, 500])('handles a text HTTP %i error before parsing JSON', async status => {
    mockFetch().mockResolvedValueOnce(new Response('internal file path', { status }))
    await expect(createFeedApi().getFeed(query)).rejects.toThrow(status === 404 ? '見つかりません' : 'HTTP 500')
  })

  it('does not fall back to local mock data on a network failure', async () => {
    mockFetch().mockRejectedValueOnce(new TypeError('Failed to fetch'))
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
    await expect(api.getFeed(repositoryQuery)).rejects.toThrow('データ形式')
    await expect(api.getFeed(repositoryQuery)).rejects.toThrow('データ形式')
    expect(fetch).toHaveBeenCalledTimes(3)
  })

  it('polls a queued job until it completes and exposes server progress', async () => {
    vi.useFakeTimers()
    mockFetch().mockResolvedValueOnce(response(ids, 202)).mockResolvedValueOnce(response(queued))
      .mockResolvedValueOnce(response(completed)).mockResolvedValueOnce(response(related))
    const onJob = vi.fn()
    const pending = createFeedApi(onJob).getFeed(repositoryQuery)
    await vi.advanceTimersByTimeAsync(1000)
    expect((await pending).items).toHaveLength(6)
    expect(onJob.mock.calls.map(([, job]) => job.stage)).toEqual(['queued', 'completed'])
  })

  it('cancels job polling without fetching another state or a feed', async () => {
    vi.useFakeTimers()
    const fetch = mockFetch().mockResolvedValueOnce(response(ids, 202)).mockResolvedValueOnce(response(queued))
    const controller = new AbortController()
    const pending = createFeedApi().getFeed(repositoryQuery, { signal: controller.signal })
    const rejection = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await vi.advanceTimersByTimeAsync(0)
    controller.abort()
    await rejection
    await vi.advanceTimersByTimeAsync(2000)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('honors cancellation before requests and passes the signal to fetch', async () => {
    const fetch = mockFetch().mockResolvedValueOnce(response(all))
    const controller = new AbortController()
    const api = createFeedApi()
    await api.getFeed(query, { signal: controller.signal })
    expect(fetch.mock.calls[0]![1]!.signal).toBe(controller.signal)
    controller.abort()
    await expect(api.getDetail({ id: 'demo-001' }, controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetch).toHaveBeenCalledTimes(1)
  })
})
