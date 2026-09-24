import type { PreviewState } from '../composables/useFeed'

/** URL-driven fixtures are available only in the development build. */
export function readPreviewOptions(search: string, development = import.meta.env.DEV) {
  const params = new URLSearchParams(development ? search : '')
  const scenario = params.get('scenario')
  const preview: PreviewState = scenario === 'loading' || scenario === 'empty' || scenario === 'error' ? scenario : 'ready'
  const stage = params.get('analysis')
  const analysisStage = stage && ['queued', 'profiling', 'matching', 'screening', 'analyzing', 'completed', 'failed'].includes(stage) ? stage : null
  return { fullFeatures: params.get('view') !== 'mvp', preview, analysisStage }
}
