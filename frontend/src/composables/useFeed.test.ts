import { effectScope, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getFeed } from '../services/feed'
import type { FeedQuery } from '../types/feed'
import { useFeed } from './useFeed'

const query = (): FeedQuery => ({ scope: 'all', search: '', severity: 'all', sort: 'newest' })
const fixture = () => getFeed(query(), { delayMs: 0 })
const flush = async () => {
  await Promise.resolve()
  await Promise.resolve()
}
const scopes: ReturnType<typeof effectScope>[] = []
afterEach(() => {
  scopes.splice(0).forEach((scope) => scope.stop())
  vi.useRealTimers()
})
function setup(loader: Parameters<typeof useFeed>[3]) {
  const scope = effectScope()
  scopes.push(scope)
  const enabled = ref(true)
  const feed = scope.run(() => useFeed(ref(query()), enabled, ref('ready'), loader))!
  return { feed, enabled, scope }
}
describe('feed request lifecycle', () => {
  it('ignores stale successful responses even when the adapter ignores cancellation', async () => {
    const results = await fixture()
    const pending: ((value: unknown) => void)[] = []
    const { feed } = setup(() => new Promise((resolve) => pending.push(resolve)))
    const fresh = feed.reload()
    pending[1]!({ ...results, items: [], total: 0, matchedTotal: 0 })
    await fresh
    pending[0]!(results)
    await flush()
    expect(feed.items.value).toEqual([])
    expect(feed.loading.value).toBe(false)
  })
  it('does not let an old rejection erase the next request', async () => {
    const results = await fixture()
    let rejectOld!: (reason: unknown) => void
    const load = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((_, reject) => {
            rejectOld = reject
          }),
      )
      .mockResolvedValue(results)
    const { feed } = setup(load)
    await feed.reload()
    rejectOld(new Error('old failure'))
    await flush()
    expect(feed.error.value).toBe('')
    expect(feed.items.value).toEqual(results.items)
  })
  it('shows malformed adapter data as a recoverable error', async () => {
    const load = vi
      .fn()
      .mockResolvedValueOnce({ items: [{}] })
      .mockResolvedValueOnce(await fixture())
    const { feed } = setup(load)
    await flush()
    expect(feed.error.value).toContain('データ形式')
    expect(feed.loading.value).toBe(false)
    await feed.reload()
    expect(feed.items.value.length).toBeGreaterThan(0)
    expect(feed.error.value).toBe('')
  })
  it('aborts on disable and disposal and ignores late responses', async () => {
    const results = await fixture()
    let complete!: (value: unknown) => void
    let signal: AbortSignal | undefined
    const { feed, enabled, scope } = setup((_, options) => {
      signal = options.signal
      return new Promise((resolve) => {
        complete = resolve
      })
    })
    enabled.value = false
    await flush()
    expect(signal?.aborted).toBe(true)
    complete(results)
    await flush()
    expect(feed.items.value).toEqual([])
    enabled.value = true
    await flush()
    scope.stop()
    expect(signal?.aborted).toBe(true)
    complete(results)
    await flush()
    expect(feed.items.value).toEqual([])
  })
})

describe('retained results and adapter boundaries', () => {
  it('keeps successful results and selection during refresh and subsequent failure', async () => {
    const results = await fixture()
    let rejectRefresh!: (error: unknown) => void
    const load = vi
      .fn()
      .mockResolvedValueOnce(results)
      .mockImplementationOnce(
        () =>
          new Promise((_, reject) => {
            rejectRefresh = reject
          }),
      )
    const { feed } = setup(load)
    await flush()
    feed.selectedId.value = results.items[3]!.id
    const pending = feed.reload()
    expect(feed.items.value).toEqual(results.items)
    expect(feed.refreshing.value).toBe(true)
    expect(feed.loading.value).toBe(false)
    rejectRefresh(new Error('secret access_token=do-not-render'))
    await pending
    expect(feed.error.value).not.toContain('secret')
    expect(feed.items.value).toEqual(results.items)
    expect(feed.selectedId.value).toBe(results.items[3]!.id)
  })
  it('does not refetch equivalent queries or lose selection when temporarily disabled', async () => {
    const results = await fixture()
    const load = vi.fn().mockResolvedValue(results)
    const scope = effectScope()
    scopes.push(scope)
    const request = ref(query())
    const enabled = ref(true)
    const feed = scope.run(() => useFeed(request, enabled, ref('ready'), load))!
    await flush()
    feed.selectedId.value = results.items[4]!.id
    request.value = { ...request.value }
    await flush()
    enabled.value = false
    await flush()
    enabled.value = true
    await flush()
    expect(load).toHaveBeenCalledTimes(1)
    expect(feed.selectedId.value).toBe(results.items[4]!.id)
  })
  it('times out even an adapter that ignores AbortSignal', async () => {
    vi.useFakeTimers()
    const scope = effectScope()
    scopes.push(scope)
    let signal: AbortSignal | undefined
    const feed = scope.run(() =>
      useFeed(
        ref(query()),
        ref(true),
        ref('ready'),
        async (_, options) => {
          signal = options.signal
          return new Promise(() => {})
        },
        100,
      ),
    )!
    await vi.advanceTimersByTimeAsync(101)
    expect(feed.error.value).toContain('時間がかかっています')
    expect(feed.loading.value).toBe(false)
    expect(signal?.aborted).toBe(true)
  })
  it('preserves server matches without locally filtering them a second time', async () => {
    const results = await fixture()
    const scope = effectScope()
    scopes.push(scope)
    const feed = scope.run(() =>
      useFeed(
        ref({ ...query(), search: 'a server full-text-only term' }),
        ref(true),
        ref('ready'),
        async () => results,
      ),
    )!
    await flush()
    expect(feed.items.value).toEqual(results.items)
  })
})

describe('pagination and profile reset', () => {
  it('appends cursor pages, deduplicates IDs and retains server totals', async () => {
    const result = await fixture()
    const first = { ...result, items: result.items.slice(0, 2), total: 12, matchedTotal: 12, nextCursor: 'page-two' }
    const second = { ...result, items: result.items.slice(1, 4), total: 12, matchedTotal: 12, nextCursor: null }
    const load = vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(second)
    const { feed } = setup(load)
    await flush()
    expect(feed.nextCursor.value).toBe('page-two')
    await feed.loadMore()
    expect(load.mock.calls[1]![0].cursor).toBe('page-two')
    expect(feed.items.value.map((item) => item.id)).toEqual(result.items.slice(0, 4).map((item) => item.id))
    expect(feed.matchedTotal.value).toBe(12)
    expect(feed.nextCursor.value).toBeNull()
  })
  it('immediately clears previous profile data before its replacement request completes', async () => {
    const result = await fixture()
    let complete!: (value: unknown) => void
    const load = vi
      .fn()
      .mockResolvedValueOnce(result)
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            complete = resolve
          }),
      )
    const { feed } = setup(load)
    await flush()
    expect(feed.items.value.length).toBeGreaterThan(0)
    const reset = feed.reset()
    expect(feed.items.value).toEqual([])
    expect(feed.selectedId.value).toBeNull()
    complete({ ...result, items: [], matchedTotal: 0, total: 0 })
    await reset
    expect(feed.items.value).toEqual([])
  })
})
