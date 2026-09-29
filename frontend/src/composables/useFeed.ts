import { computed, onScopeDispose, ref, watch, type Ref } from 'vue'
import { getFeed } from '../services/feed'
import { parseFeedResult, type FeedLoader } from '../services/feedContract'
import type { FeedItem, FeedQuery } from '../types/feed'

export type PreviewState = 'ready' | 'loading' | 'empty' | 'error'

export function useFeed(query: Ref<FeedQuery>, enabled: Ref<boolean>, preview: Ref<PreviewState>, loadFeed: FeedLoader = getFeed) {
  const items = ref<FeedItem[]>([])
  const total = ref(0)
  const selectedId = ref<string | null>(null)
  const loading = ref(false)
  const error = ref('')
  const selected = computed(() => items.value.find(item => item.id === selectedId.value) ?? null)
  let controller: AbortController | undefined
  let displayedQuery: string | undefined
  let disposed = false
  const queryKey = () => JSON.stringify([
    query.value.scope, query.value.repositoryUrl ?? '', query.value.search, query.value.severity, query.value.sort,
  ])

  async function reload() {
    if (disposed) return
    controller?.abort()
    controller = undefined
    const currentQuery = queryKey()
    // 条件が変わった一覧は次の描画前に消す。同じ条件の再読込では取得済みの内容を残す。
    if (displayedQuery !== currentQuery) {
      displayedQuery = currentQuery
      items.value = []
      total.value = 0
      error.value = ''
    }
    if (!enabled.value) { loading.value = false; return }
    const request = new AbortController()
    controller = request
    error.value = ''
    loading.value = true
    if (preview.value === 'loading') return

    const isCurrent = () => !disposed && controller === request && !request.signal.aborted
    const fail = (cause: unknown) => {
      error.value = cause instanceof Error ? cause.message : 'フィードを読み込めませんでした。'
      loading.value = false
    }
    const accept = (response: unknown) => {
      if (!isCurrent()) return
      const result = parseFeedResult(response)
      items.value = result.items
      total.value = result.total
      if (!items.value.some(item => item.id === selectedId.value)) {
        selectedId.value = items.value[0]?.id ?? null
      }
    }
    try {
      const response = await loadFeed({ ...query.value }, {
        signal: request.signal,
        scenario: preview.value,
        onProgress: result => {
          if (!isCurrent()) return
          try {
            accept(result)
          } catch (cause) {
            // 途中結果にも最終応答と同じ検証を行い、不正な結果の後続更新を止める。
            fail(cause)
            request.abort()
            controller = undefined
          }
        },
      })
      accept(response)
    } catch (cause) {
      if (!isCurrent()) return
      fail(cause)
    } finally {
      if (isCurrent()) {
        loading.value = false
        controller = undefined
      }
    }
  }
  watch([queryKey, enabled, preview], reload, { immediate: true, flush: 'sync' })
  onScopeDispose(() => {
    disposed = true
    controller?.abort()
    controller = undefined
    loading.value = false
  })
  return { items, total, selectedId, selected, loading, error, reload }
}
