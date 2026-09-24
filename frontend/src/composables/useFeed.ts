import { computed, onScopeDispose, ref, watch, type Ref } from 'vue'
import { getFeed } from '../services/feed'
import type { FeedItem, FeedQuery } from '../types/feed'

export type PreviewState = 'ready' | 'loading' | 'empty' | 'error'

export function useFeed(query: Ref<FeedQuery>, enabled: Ref<boolean>, preview: Ref<PreviewState>) {
  const items = ref<FeedItem[]>([])
  const total = ref(0)
  const selectedId = ref<string | null>(null)
  const loading = ref(false)
  const error = ref('')
  const selected = computed(() => items.value.find(item => item.id === selectedId.value) ?? null)
  let controller: AbortController | undefined

  async function reload() {
    controller?.abort()
    const request = new AbortController()
    controller = request
    error.value = ''
    items.value = []
    total.value = 0
    if (!enabled.value) { loading.value = false; selectedId.value = null; return }
    loading.value = true
    if (preview.value === 'loading') return
    try {
      const result = await getFeed(query.value, { signal: request.signal, scenario: preview.value })
      if (request.signal.aborted) return
      items.value = result.items
      total.value = result.total
      if (!items.value.some(item => item.id === selectedId.value)) {
        selectedId.value = items.value[0]?.id ?? null
      }
    } catch (cause) {
      if (request.signal.aborted) return
      error.value = cause instanceof Error ? cause.message : 'フィードを読み込めませんでした。'
      selectedId.value = null
    } finally {
      if (!request.signal.aborted) loading.value = false
    }
  }
  watch([query, enabled, preview], reload, { immediate: true })
  onScopeDispose(() => controller?.abort())
  return { items, total, selectedId, selected, loading, error, reload }
}
