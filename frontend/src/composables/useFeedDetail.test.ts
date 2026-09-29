import { effectScope, ref } from 'vue'
import { afterEach, expect, it, vi } from 'vitest'
import { mockFeed } from '../mocks/feed'
import type { FeedItem } from '../types/feed'
import type { DetailTarget } from '../services/feedApi'
import { useFeedDetail } from './useFeedDetail'

const scopes: ReturnType<typeof effectScope>[] = []
const flush = async () => { await Promise.resolve(); await Promise.resolve() }
afterEach(() => scopes.splice(0).forEach(scope => scope.stop()))

it('ignores a stale detail after the user selects another article', async () => {
  const scope = effectScope(); scopes.push(scope)
  const target = ref<DetailTarget | null>({ id: 'demo-001' })
  const pending: { resolve: (item: FeedItem) => void; signal: AbortSignal }[] = []
  const detail = scope.run(() => useFeedDetail(target, (_, signal) => new Promise(resolve => pending.push({ resolve, signal }))))!
  target.value = { id: 'demo-002' }
  expect(pending[0]!.signal.aborted).toBe(true)
  pending[1]!.resolve(mockFeed[1]!)
  await flush()
  pending[0]!.resolve(mockFeed[0]!)
  await flush()
  expect(detail.item.value?.id).toBe('demo-002')
  expect(detail.loading.value).toBe(false)
})

it('clears old content on a repository switch and allows retrying failures', async () => {
  const scope = effectScope(); scopes.push(scope)
  const target = ref<DetailTarget | null>({ id: 'demo-001' })
  let fail = false
  const detail = scope.run(() => useFeedDetail(target, async () => {
    if (fail) throw new Error('offline')
    return mockFeed[0]!
  }))!
  await flush()
  expect(detail.item.value).not.toBeNull()
  fail = true
  target.value = { id: 'demo-001', repositoryUrl: 'https://github.com/example/mock-service' }
  expect(detail.item.value).toBeNull()
  await flush()
  expect(detail.error.value).toBe('offline')
  fail = false
  await detail.reload()
  expect(detail.error.value).toBe('')
  expect(detail.item.value?.id).toBe('demo-001')
  target.value = null
  expect(detail.item.value).toBeNull()
  expect(detail.loading.value).toBe(false)
})

it('keeps the loaded article when a new target object identifies the same article', async () => {
  const scope = effectScope(); scopes.push(scope)
  const target = ref<DetailTarget | null>({ id: 'demo-001', repositoryUrl: 'https://github.com/example/first' })
  const load = vi.fn(async () => mockFeed[0]!)
  const detail = scope.run(() => useFeedDetail(target, load))!
  await flush()
  const firstItem = detail.item.value
  target.value = { id: 'demo-001', repositoryUrl: 'https://github.com/example/first' }
  expect(detail.item.value).toBe(firstItem)
  expect(detail.loading.value).toBe(false)
  expect(load).toHaveBeenCalledTimes(1)
  target.value.repositoryUrl = 'https://github.com/example/second'
  expect(detail.item.value).toBeNull()
  expect(load).toHaveBeenCalledTimes(2)
  await flush()
  expect(detail.item.value?.id).toBe('demo-001')
})

it('does not cancel an in-flight detail for an equivalent target object', async () => {
  const scope = effectScope(); scopes.push(scope)
  const target = ref<DetailTarget | null>({ id: 'demo-001' })
  let complete!: (item: FeedItem) => void
  let signal!: AbortSignal
  const load = vi.fn((_: DetailTarget, requestSignal: AbortSignal) => {
    signal = requestSignal
    return new Promise<FeedItem>(resolve => { complete = resolve })
  })
  const detail = scope.run(() => useFeedDetail(target, load))!
  target.value = { id: 'demo-001' }
  expect(signal.aborted).toBe(false)
  expect(load).toHaveBeenCalledTimes(1)
  complete(mockFeed[0]!)
  await flush()
  expect(detail.item.value?.id).toBe('demo-001')
})

it('cancels when the target is cleared and on disposal, ignoring late errors and results', async () => {
  const scope = effectScope(); scopes.push(scope)
  const target = ref<DetailTarget | null>({ id: 'demo-001' })
  const pending: { signal: AbortSignal; resolve: (item: FeedItem) => void; reject: (cause: unknown) => void }[] = []
  const load = vi.fn((_: DetailTarget, signal: AbortSignal) => new Promise<FeedItem>((resolve, reject) => pending.push({ signal, resolve, reject })))
  const detail = scope.run(() => useFeedDetail(target, load))!
  target.value = null
  expect(pending[0]!.signal.aborted).toBe(true)
  pending[0]!.reject(new Error('stale failure'))
  await flush()
  expect(detail.item.value).toBeNull()
  expect(detail.error.value).toBe('')
  target.value = { id: 'demo-002' }
  scope.stop()
  expect(pending[1]!.signal.aborted).toBe(true)
  pending[1]!.resolve(mockFeed[1]!)
  await flush()
  await detail.reload()
  expect(detail.item.value).toBeNull()
  expect(detail.loading.value).toBe(false)
  expect(load).toHaveBeenCalledTimes(2)
})
