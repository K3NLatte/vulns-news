import { onScopeDispose, ref, watch, type Ref } from 'vue'
import type { FeedItem } from '../types/feed'
import type { DetailTarget } from '../services/feedApi'

type DetailLoader = (target: DetailTarget, signal: AbortSignal) => Promise<FeedItem>

export function useFeedDetail(target: Ref<DetailTarget | null>, load: DetailLoader) {
  const item = ref<FeedItem | null>(null)
  const loading = ref(false)
  const error = ref('')
  let controller: AbortController | undefined

  async function reload() {
    controller?.abort()
    const request = new AbortController()
    controller = request
    item.value = null
    error.value = ''
    const current = target.value
    if (!current) { loading.value = false; return }
    loading.value = true
    try {
      const result = await load(current, request.signal)
      if (!request.signal.aborted) item.value = result
    } catch (cause) {
      if (!request.signal.aborted) error.value = cause instanceof Error ? cause.message : '記事を読み込めませんでした。'
    } finally {
      if (!request.signal.aborted) loading.value = false
    }
  }
  // Clear the previous article before the next render, including repository switches.
  watch(target, reload, { immediate: true, flush: 'sync' })
  onScopeDispose(() => controller?.abort())
  return { item, loading, error, reload }
}
