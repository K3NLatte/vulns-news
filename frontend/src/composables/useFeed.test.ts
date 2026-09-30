import { effectScope, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getFeed } from '../services/feed'
import type { FeedOptions, FeedQuery, FeedResult } from '../types/feed'
import { useFeed } from './useFeed'

const query = (): FeedQuery => ({ scope: 'all', search: '', severity: 'all', sort: 'newest' })
const fixture = () => getFeed(query(), { delayMs: 0 })
const flush = async () => { await Promise.resolve(); await Promise.resolve() }
const scopes: ReturnType<typeof effectScope>[] = []
afterEach(() => { scopes.splice(0).forEach(scope => scope.stop()) })
function setup(loader: Parameters<typeof useFeed>[3]) {
  const scope = effectScope(); scopes.push(scope)
  const enabled = ref(true)
  const currentQuery = ref(query())
  const feed = scope.run(() => useFeed(currentQuery, enabled, ref('ready'), loader))!
  return { feed, enabled, scope, currentQuery }
}
describe('feed request lifecycle', () => {
  it('ignores stale successful responses even when the adapter ignores cancellation', async () => {
    const results = await fixture()
    const pending: ((value: unknown) => void)[] = []
    const { feed } = setup(() => new Promise(resolve => pending.push(resolve)))
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
    const load = vi.fn().mockImplementationOnce(() => new Promise((_, reject) => { rejectOld = reject })).mockResolvedValue(results)
    const { feed } = setup(load)
    await feed.reload()
    rejectOld(new Error('old failure'))
    await flush()
    expect(feed.error.value).toBe('')
    expect(feed.items.value).toEqual(results.items)
  })
  it('shows malformed adapter data as a recoverable error', async () => {
    const load = vi.fn().mockResolvedValueOnce({ items: [{}] }).mockResolvedValueOnce(await fixture())
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
      return new Promise(resolve => { complete = resolve })
    })
    enabled.value = false
    await flush()
    expect(signal?.aborted).toBe(true)
    complete(results); await flush()
    expect(feed.items.value).toEqual([])
    enabled.value = true; await flush()
    scope.stop()
    expect(signal?.aborted).toBe(true)
    complete(results); await flush()
    expect(feed.items.value).toEqual([])
  })
  it('keeps the current list and selection during a refresh and after a refresh error', async () => {
    const result = await fixture()
    let rejectRefresh!: (reason: unknown) => void
    const load = vi.fn().mockResolvedValueOnce(result).mockImplementationOnce(() => new Promise((_, reject) => { rejectRefresh = reject }))
    const { feed } = setup(load)
    await flush()
    feed.selectedId.value = result.items[1]!.id
    const refresh = feed.reload()
    expect(feed.loading.value).toBe(true)
    expect(feed.items.value).toEqual(result.items)
    expect(feed.total.value).toBe(result.total)
    expect(feed.selectedId.value).toBe(result.items[1]!.id)
    rejectRefresh(new Error('offline'))
    await refresh
    expect(feed.error.value).toBe('offline')
    expect(feed.items.value).toEqual(result.items)
    expect(feed.selectedId.value).toBe(result.items[1]!.id)
    expect(feed.loading.value).toBe(false)
  })
  it('shows validated progress while loading and preserves partial results on failure', async () => {
    const result = await fixture()
    const partial = { ...result, items: result.items.slice(0, 2), matchedTotal: 2 }
    let progress!: NonNullable<FeedOptions['onProgress']>
    let reject!: (reason: unknown) => void
    const { feed } = setup((_, options) => {
      progress = options.onProgress!
      return new Promise((_, rejectRequest) => { reject = rejectRequest })
    })
    progress(partial)
    expect(feed.items.value).toEqual(partial.items)
    expect(feed.loading.value).toBe(true)
    feed.selectedId.value = partial.items[1]!.id
    reject(new Error('poll failed'))
    await flush()
    expect(feed.items.value).toEqual(partial.items)
    expect(feed.total.value).toBe(partial.total)
    expect(feed.selectedId.value).toBe(partial.items[1]!.id)
    expect(feed.error.value).toBe('poll failed')
    expect(feed.loading.value).toBe(false)
  })
  it('clears a previous repository synchronously and ignores its late progress and completion', async () => {
    const result = await fixture()
    const pending: { options: FeedOptions; resolve: (value: unknown) => void }[] = []
    const { feed, currentQuery } = setup((_, options) => new Promise(resolve => pending.push({ options, resolve })))
    pending[0]!.options.onProgress!(result)
    currentQuery.value = { ...query(), scope: 'repository', repositoryUrl: 'https://github.com/example/first' }
    expect(feed.items.value).toEqual([])
    expect(feed.total.value).toBe(0)
    expect(pending[0]!.options.signal?.aborted).toBe(true)
    const firstRepository = { ...result, items: [result.items[1]!], matchedTotal: 1 }
    pending[1]!.options.onProgress!(firstRepository)
    currentQuery.value = { ...currentQuery.value, repositoryUrl: 'https://github.com/example/second' }
    expect(feed.items.value).toEqual([])
    expect(pending[1]!.options.signal?.aborted).toBe(true)
    pending[0]!.options.onProgress!(result)
    pending[1]!.options.onProgress!(firstRepository)
    pending[0]!.resolve(result)
    pending[1]!.resolve(firstRepository)
    await flush()
    expect(feed.items.value).toEqual([])
    const secondRepository = { ...result, items: [result.items[2]!], matchedTotal: 1 }
    pending[2]!.resolve(secondRepository)
    await flush()
    expect(feed.items.value).toEqual(secondRepository.items)
    expect(feed.selectedId.value).toBe(result.items[2]!.id)
  })
  it('rejects malformed progress without replacing the last valid list', async () => {
    const result = await fixture()
    let options!: FeedOptions
    let complete!: (value: unknown) => void
    const { feed } = setup((_, requestOptions) => {
      options = requestOptions
      return new Promise(resolve => { complete = resolve })
    })
    options.onProgress!(result)
    const selection = feed.selectedId.value
    expect(() => options.onProgress!({ items: [{}] } as FeedResult)).not.toThrow()
    expect(options.signal?.aborted).toBe(true)
    expect(feed.error.value).toContain('データ形式')
    expect(feed.loading.value).toBe(false)
    expect(feed.items.value).toEqual(result.items)
    expect(feed.selectedId.value).toBe(selection)
    const empty = { ...result, items: [], total: 0, matchedTotal: 0 }
    options.onProgress!(empty)
    complete(empty)
    await flush()
    expect(feed.items.value).toEqual(result.items)
    expect(feed.error.value).toContain('データ形式')
  })
  it('preserves the list while disabled and reloads the same query without clearing on return', async () => {
    const result = await fixture()
    const pending: { options: FeedOptions; resolve: (value: unknown) => void }[] = []
    const load = vi.fn((_: FeedQuery, options: FeedOptions) => new Promise(resolve => pending.push({ options, resolve })))
    const { feed, enabled, currentQuery } = setup(load)
    pending[0]!.options.onProgress!(result)
    feed.selectedId.value = result.items[1]!.id
    enabled.value = false
    expect(pending[0]!.options.signal?.aborted).toBe(true)
    expect(feed.items.value).toEqual(result.items)
    expect(feed.loading.value).toBe(false)
    pending[0]!.options.onProgress!({ ...result, items: [], total: 0, matchedTotal: 0 })
    expect(feed.items.value).toEqual(result.items)
    currentQuery.value = { ...currentQuery.value }
    enabled.value = true
    expect(load).toHaveBeenCalledTimes(2)
    expect(feed.loading.value).toBe(true)
    expect(feed.items.value).toEqual(result.items)
    expect(feed.selectedId.value).toBe(result.items[1]!.id)
    pending[1]!.resolve(result)
    await flush()
    currentQuery.value = { ...currentQuery.value }
    expect(load).toHaveBeenCalledTimes(2)
    enabled.value = false
    currentQuery.value = { ...query(), scope: 'repository', repositoryUrl: 'https://github.com/example/changed' }
    expect(feed.items.value).toEqual([])
    expect(load).toHaveBeenCalledTimes(2)
  })
  it('ignores progress after completion and prevents loading again after disposal', async () => {
    const result = await fixture()
    let progress!: NonNullable<FeedOptions['onProgress']>
    const load = vi.fn(async (_: FeedQuery, options: FeedOptions) => {
      progress = options.onProgress!
      return result
    })
    const { feed, scope } = setup(load)
    await flush()
    progress({ ...result, items: [], total: 0, matchedTotal: 0 })
    expect(feed.items.value).toEqual(result.items)
    scope.stop()
    await feed.reload()
    expect(load).toHaveBeenCalledTimes(1)
    expect(feed.loading.value).toBe(false)
  })
})
