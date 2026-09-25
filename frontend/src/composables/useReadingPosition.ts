import { nextTick, onScopeDispose, watch, type Ref } from 'vue'
import type { AppRoute } from './useNavigation'
interface ReadingPosition {
  y: number
  detail: number
  body: number
  selected: string | null
  focus: string
}

/** History entries own their reading position; browser restoration is disabled while mounted. */
export function useReadingPosition(
  route: Ref<AppRoute>,
  entryId: Ref<string>,
  loading: Ref<boolean>,
  selectedId: Ref<string | null>,
) {
  const entries = new Map<string, ReadingPosition>()
  const routes = new Map<string, ReadingPosition>()
  let currentId = entryId.value
  let currentHash = window.location.hash
  let restoring = false
  let pending: ReadingPosition | undefined
  let generation = 0
  const previousRestoration = history.scrollRestoration
  history.scrollRestoration = 'manual'
  function capture() {
    if (restoring) return
    const active = document.activeElement as HTMLElement | null
    const position = {
      y: window.scrollY,
      detail: document.querySelector('.feed-detail')?.scrollTop ?? 0,
      body: document.querySelector('.detail-content')?.scrollTop ?? 0,
      selected: selectedId.value,
      focus: active?.id ?? '',
    }
    entries.set(currentId, position)
    routes.set(currentHash, position)
  }
  async function restore() {
    const version = ++generation
    await nextTick()
    if (loading.value || version !== generation) return
    const position = pending
    if (position?.selected) selectedId.value = position.selected
    await nextTick()
    if (version !== generation) return
    window.scrollTo({ top: position?.y ?? 0 })
    const detail = document.querySelector('.feed-detail')
    const body = document.querySelector('.detail-content')
    if (detail) detail.scrollTop = position?.detail ?? 0
    if (body) body.scrollTop = position?.body ?? 0
    const remembered = position?.focus ? document.getElementById(position.focus) : null
    const listItem =
      position?.selected && ['feed', 'repositories', 'saved'].includes(route.value.page)
        ? document.getElementById('article-' + position.selected)
        : null
    let target =
      remembered ??
      listItem ??
      (route.value.page === 'article' ? document.getElementById('detail-title') : null) ??
      document.querySelector<HTMLElement>('main h1')
    if (target) {
      const bounds = target.getBoundingClientRect()
      if (bounds.bottom <= 0 || bounds.top >= window.innerHeight) {
        // Keep the reading position and focus content that is actually visible.
        const visible = [...document.querySelectorAll<HTMLElement>('main h1, main h2, main h3, .feed-item')].find(
          (element) => {
            const box = element.getBoundingClientRect()
            return box.height > 0 && box.top >= 0 && box.top < window.innerHeight
          },
        )
        target = visible ?? document.querySelector<HTMLElement>('main') ?? target
      }
      if (!target.matches('a,button,input,select,textarea')) target.setAttribute('tabindex', '-1')
      target.focus({ preventScroll: true })
    }
    pending = undefined
    restoring = false
    capture()
  }
  watch(
    entryId,
    () => {
      capture()
      restoring = true
      currentId = entryId.value
      currentHash = window.location.hash
      pending = entries.get(currentId) ?? (route.value.page !== 'article' ? routes.get(currentHash) : undefined)
      void restore()
    },
    { flush: 'pre' },
  )
  watch(loading, (value) => {
    if (!value && restoring) void restore()
  })
  window.addEventListener('scroll', capture, { passive: true, capture: true })
  window.addEventListener('pagehide', capture)
  document.addEventListener('focusin', capture)
  onScopeDispose(() => {
    generation++
    history.scrollRestoration = previousRestoration
    window.removeEventListener('scroll', capture, true)
    window.removeEventListener('pagehide', capture)
    document.removeEventListener('focusin', capture)
  })
  return { capture }
}
