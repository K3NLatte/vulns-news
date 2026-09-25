import { computed, onScopeDispose, ref, shallowRef, watch, type Ref } from 'vue'
import { getFeed } from '../services/feed'
import { parseFeedResult, type FeedLoader } from '../services/feedContract'
import { RequestError, requestErrorMessage } from '../utils/requestError'
import type { FeedItem, FeedQuery, FeedResult } from '../types/feed'

export type PreviewState = 'ready' | 'loading' | 'empty' | 'error'

export function useFeed(
  query: Ref<FeedQuery>,
  enabled: Ref<boolean>,
  preview: Ref<PreviewState>,
  loadFeed: FeedLoader = getFeed,
  timeoutMs = 15_000,
) {
  const items = shallowRef<FeedItem[]>([])
  const total = ref(0)
  const matchedTotal = ref(0)
  const rejectedCount = ref(0)
  const nextCursor = ref<string | null>(null)
  const selectedId = ref<string | null>(null)
  const loading = ref(false)
  const refreshing = ref(false)
  const error = ref('')
  const selected = computed(() => items.value.find((item) => item.id === selectedId.value) ?? null)
  const cache = new Map<string, FeedResult>()
  const queryKey = computed(() =>
    JSON.stringify([
      query.value.scope,
      query.value.repositoryUrl ?? '',
      query.value.search,
      query.value.severity,
      query.value.sort,
    ]),
  )
  let controller: AbortController | undefined
  let shownContext = ''
  let pendingKey = ''
  let disposed = false

  function apply(result: FeedResult) {
    items.value = result.items
    total.value = result.total
    matchedTotal.value = result.matchedTotal
    rejectedCount.value = result.rejectedCount ?? 0
    nextCursor.value = result.nextCursor ?? null
    if (!selectedId.value) selectedId.value = result.items[0]?.id ?? null
  }
  async function reload(force = true, append = false) {
    const key = queryKey.value + ':' + preview.value
    const cursor = append ? nextCursor.value : undefined
    if (append && (!cursor || refreshing.value || loading.value)) return
    if (!force && pendingKey === key && enabled.value) return
    controller?.abort()
    pendingKey = ''
    if (!enabled.value || disposed) {
      loading.value = false
      refreshing.value = false
      return
    }
    const context = JSON.stringify([query.value.scope, query.value.repositoryUrl ?? ''])
    if (shownContext && shownContext !== context) {
      items.value = []
      total.value = 0
      matchedTotal.value = 0
      rejectedCount.value = 0
      nextCursor.value = null
    }
    shownContext = context
    error.value = ''
    if (!append && !force && cache.has(key)) {
      apply(cache.get(key)!)
      loading.value = false
      refreshing.value = false
      return
    }
    const request = new AbortController()
    controller = request
    pendingKey = key
    loading.value = items.value.length === 0
    refreshing.value = !loading.value
    if (preview.value === 'loading') {
      items.value = []
      loading.value = true
      refreshing.value = false
      return
    }
    let timer: ReturnType<typeof setTimeout> | undefined
    let cancelWait: (() => void) | undefined
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new RequestError('timeout')), timeoutMs)
      })
      const cancelled = new Promise<never>((_, reject) => {
        cancelWait = () => reject(new DOMException('Cancelled', 'AbortError'))
        request.signal.addEventListener('abort', cancelWait, { once: true })
      })
      const response = await Promise.race([
        loadFeed(
          { ...query.value, ...(cursor ? { cursor } : {}) },
          { signal: request.signal, scenario: preview.value },
        ),
        timeout,
        cancelled,
      ])
      if (request.signal.aborted || disposed) return
      let result: FeedResult
      try {
        result = parseFeedResult(response)
      } catch {
        throw new RequestError('contract')
      }
      if (append)
        result = {
          ...result,
          items: [...new Map([...items.value, ...result.items].map((item) => [item.id, item])).values()],
          rejectedCount: rejectedCount.value + (result.rejectedCount ?? 0),
        }
      cache.set(key, result)
      if (cache.size > 12) cache.delete(cache.keys().next().value!)
      apply(result)
    } catch (cause) {
      if (request.signal.aborted || disposed) return
      error.value = requestErrorMessage(cause)
    } finally {
      clearTimeout(timer)
      if (cancelWait) request.signal.removeEventListener('abort', cancelWait)
      if (controller === request) {
        loading.value = false
        refreshing.value = false
        pendingKey = ''
      }
      request.abort()
    }
  }
  function invalidate() {
    cache.clear()
    return reload()
  }
  function reset() {
    controller?.abort()
    cache.clear()
    items.value = []
    selectedId.value = null
    total.value = 0
    matchedTotal.value = 0
    rejectedCount.value = 0
    nextCursor.value = null
    error.value = ''
    return reload()
  }
  watch([queryKey, enabled, preview], () => void reload(false), { immediate: true })
  onScopeDispose(() => {
    disposed = true
    controller?.abort()
  })
  return {
    items,
    total,
    matchedTotal,
    rejectedCount,
    nextCursor,
    selectedId,
    selected,
    loading,
    refreshing,
    error,
    reload,
    invalidate,
    reset,
    loadMore: () => reload(true, true),
  }
}
