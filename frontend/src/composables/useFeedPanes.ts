import { computed, nextTick, onScopeDispose, ref, watch, type Ref } from 'vue'

/** The feed scrolls with the document; the detail fills the visible area as its header moves up. */
export function useFeedPanes(
  workspace: Ref<HTMLElement | null>,
  controls: Ref<HTMLElement | null>,
  enabled: Ref<boolean>,
) {
  const height = ref(0)
  const splitView = ref(false)
  const fullPaneScroll = ref(false)
  const observer = new ResizeObserver(scheduleMeasure)
  const detailObserver = new ResizeObserver(scheduleMeasure)
  const mutationObserver = new MutationObserver(observeDetail)
  let detailHeader: Element | null = null
  let detailActions: Element | null = null
  let frame: number | null = null
  let disposed = false

  function observeDetail() {
    const header = workspace.value?.querySelector('.detail-header') ?? null
    const actions = workspace.value?.querySelector('.detail-topline') ?? null
    if (header === detailHeader && actions === detailActions) return
    detailObserver.disconnect()
    detailHeader = header
    detailActions = actions
    if (header) detailObserver.observe(header)
    if (actions) detailObserver.observe(actions)
    scheduleMeasure()
  }

  function measure() {
    const textScale = parseFloat(getComputedStyle(document.documentElement).fontSize) / 16
    // Enlarged text needs more height for the fixed article heading and readable body.
    splitView.value = enabled.value && window.innerWidth >= 1000 && window.innerHeight >= 500 * textScale
    if (!splitView.value || !workspace.value) {
      fullPaneScroll.value = false
      return
    }
    const top = Math.max(16, workspace.value.getBoundingClientRect().top)
    height.value = Math.max(280, Math.floor(window.innerHeight - top - 16))
    const fixedHeight =
      (detailHeader?.getBoundingClientRect().height ?? 0) + (detailActions?.getBoundingClientRect().height ?? 0)
    // Very long titles must not consume the whole pane and make the body unreachable.
    // Do not change scroll containers when the document moves: that loses reading position.
    fullPaneScroll.value = fixedHeight + 160 * textScale > window.innerHeight - 32
  }
  function scheduleMeasure() {
    if (disposed || frame !== null) return
    frame = requestAnimationFrame(() => {
      frame = null
      measure()
    })
  }
  watch(
    [workspace, controls, enabled],
    async () => {
      await nextTick()
      if (disposed) return
      observer.disconnect()
      mutationObserver.disconnect()
      if (workspace.value) mutationObserver.observe(workspace.value, { childList: true, subtree: true })
      observeDetail()
      if (controls.value) observer.observe(controls.value)
      const header = document.querySelector('.app-header')
      if (header) observer.observe(header)
      measure()
    },
    { immediate: true },
  )
  window.addEventListener('resize', scheduleMeasure)
  window.addEventListener('scroll', scheduleMeasure, { passive: true })
  onScopeDispose(() => {
    disposed = true
    observer.disconnect()
    detailObserver.disconnect()
    mutationObserver.disconnect()
    if (frame !== null) cancelAnimationFrame(frame)
    window.removeEventListener('resize', scheduleMeasure)
    window.removeEventListener('scroll', scheduleMeasure)
  })
  return {
    splitView,
    fullPaneScroll,
    paneStyle: computed(() => (splitView.value ? { '--detail-height': height.value + 'px' } : undefined)),
  }
}
