import { effectScope, ref } from 'vue'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { getFeed } from '../services/feed'
import type { FeedQuery } from '../types/feed'
import { useFeed } from './useFeed'

const query = (): FeedQuery => ({ scope: 'all', search: '', severity: 'all', sort: 'newest' })
const fixture = () => getFeed(query(), { delayMs: 0 })
const flush = async () => { await Promise.resolve(); await Promise.resolve() }
const scopes: ReturnType<typeof effectScope>[] = []
afterEach(() => { scopes.splice(0).forEach(scope => scope.stop()) })
function setup(loader: Parameters<typeof useFeed>[3]) {
  const scope = effectScope(); scopes.push(scope)
  const enabled = ref(true)
  const feed = scope.run(() => useFeed(ref(query()), enabled, ref('ready'), loader))!
  return { feed, enabled, scope }
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
})
