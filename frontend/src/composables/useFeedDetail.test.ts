import { effectScope, ref } from 'vue'
import { afterEach, expect, it } from 'vitest'
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
