import { onScopeDispose, ref, watch, type Ref } from 'vue'
import type { FeedItem } from '../types/feed'
import type { DetailTarget } from '../services/feedApi'

type DetailLoader = (target: DetailTarget, signal: AbortSignal) => Promise<FeedItem>

export function useFeedDetail(target: Ref<DetailTarget | null>, load: DetailLoader) {
  const item = ref<FeedItem | null>(null)
  const loading = ref(false)
  const error = ref('')
  let controller: AbortController | undefined
  let disposed = false

  async function reload() {
    if (disposed) return
    controller?.abort()
    const request = new AbortController()
    controller = request
    item.value = null
    error.value = ''
    if (!target.value) { loading.value = false; return }
    const current = { ...target.value }
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
  // 同じ記事のオブジェクト再生成では詳細を消さず、記事やリポジトリの変更時だけ読み直す。
  watch([() => target.value?.id ?? null, () => target.value?.repositoryUrl ?? null], reload, { immediate: true, flush: 'sync' })
  onScopeDispose(() => {
    disposed = true
    controller?.abort()
    loading.value = false
  })
  return { item, loading, error, reload }
}
