import { computed, nextTick, onScopeDispose, ref, watch, type Ref } from 'vue'

/** The feed scrolls with the document; the detail fills the visible area as its header moves up. */
export function useFeedPanes(
  workspace: Ref<HTMLElement | null>,
  controls: Ref<HTMLElement | null>,
  enabled: Ref<boolean>,
) {
  const height = ref(0)
  const splitView = ref(false)
  const observer = new ResizeObserver(measure)
  let frame: number | null = null

  function measure() {
    const textScale = parseFloat(getComputedStyle(document.documentElement).fontSize) / 16
    // Enlarged text needs more height for the fixed article heading and readable body.
    splitView.value = enabled.value && window.innerWidth >= 1000 && window.innerHeight >= 500 * textScale
    if (!splitView.value || !workspace.value) return
    const top = Math.max(16, workspace.value.getBoundingClientRect().top)
    height.value = Math.max(280, Math.floor(window.innerHeight - top - 16))
  }
  function scheduleMeasure() {
    if (frame !== null) return
    frame = requestAnimationFrame(() => { frame = null; measure() })
  }
  watch([workspace, controls, enabled], async () => {
    await nextTick()
    observer.disconnect()
    if (controls.value) observer.observe(controls.value)
    const header = document.querySelector('.app-header')
    if (header) observer.observe(header)
    measure()
  }, { immediate: true })
  window.addEventListener('resize', scheduleMeasure)
  window.addEventListener('scroll', scheduleMeasure, { passive: true })
  onScopeDispose(() => {
    observer.disconnect()
    if (frame !== null) cancelAnimationFrame(frame)
    window.removeEventListener('resize', scheduleMeasure)
    window.removeEventListener('scroll', scheduleMeasure)
  })
  return { splitView, paneStyle: computed(() => splitView.value ? { '--detail-height': height.value + 'px' } : undefined) }
}
