import { computed, ref, type Ref } from 'vue'
import type { FeedItem } from '../types/feed'
import type { AnalysisSnapshot, AnalysisStage } from '../types/analysis'

export type AnalysisFilter = 'all' | 'analyzed' | 'pending'
const stages: AnalysisStage[] = ['queued', 'profiling', 'matching', 'screening', 'analyzing', 'completed', 'failed']
// Fixed review fixtures. These are neither dependency rules nor an API contract.
const partialAnalyzedIds = new Set(['demo-002', 'demo-003', 'demo-008'])

export function useAnalysisPreview(source: Ref<FeedItem[]>, personalized: Ref<boolean>, requestedStage: string | null, live?: Ref<AnalysisSnapshot | null>) {
  const previewStage = ref<AnalysisStage>(stages.find(value => value === requestedStage) ?? 'completed')
  const stage = computed(() => live?.value?.stage ?? previewStage.value)
  const filter = ref<AnalysisFilter>('all')
  const items = computed<FeedItem[]>(() => {
    if (!personalized.value) return source.value
    const classified = source.value.map(item => ({
      ...item,
      repositoryAnalysis: item.repositoryAnalysis === 'analyzed' && item.assessment !== 'unverified'
        ? 'analyzed' as const : 'pending' as const,
    }))
    if (live) return classified
    if (['queued', 'profiling', 'matching'].includes(stage.value)) return []
    if (stage.value === 'screening') return classified.filter(item => item.repositoryAnalysis === 'pending')
    if (stage.value === 'analyzing' || stage.value === 'failed') {
      return classified.filter(item => partialAnalyzedIds.has(item.id) || item.repositoryAnalysis === 'pending')
    }
    return classified
  })
  const analyzedCount = computed(() => items.value.filter(item => item.repositoryAnalysis === 'analyzed').length)
  const pendingCount = computed(() => items.value.filter(item => item.repositoryAnalysis === 'pending').length)
  const snapshot = computed<AnalysisSnapshot>(() => live?.value ?? ({
    stage: stage.value,
    hasAvailableResults: items.value.length > 0,
    // Result counts are already present in the filter controls below the status.
  }))
  function retry() { previewStage.value = 'analyzing' }
  return { stage, filter, items, analyzedCount, pendingCount, snapshot, retry }
}
