import { describe, expect, it } from 'vitest'
import { ref } from 'vue'
import { mockFeed } from '../mocks/feed'
import type { FeedItem } from '../types/feed'
import { useAnalysisPreview } from './useAnalysisPreview'

describe('useAnalysisPreview', () => {
  it('keeps an available article accessible when searching, reordering, and opening its full feed', () => {
    for (const stage of ['analyzing', 'failed']) {
      const articles = structuredClone(mockFeed)
      const source = ref<FeedItem[]>(articles)
      const preview = useAnalysisPreview(source, ref(true), stage)
      const targetId = 'demo-002'
      const isAvailable = () => preview.items.value.some(item => item.id === targetId)

      expect(isAvailable()).toBe(true)
      source.value = [...articles].reverse()
      expect(isAvailable()).toBe(true)
      source.value = articles.filter(item => item.id === targetId)
      expect(isAvailable()).toBe(true)
      source.value = articles
      expect(isAvailable()).toBe(true)
    }
  })

  it('withholds early repository results while keeping the general feed available', () => {
    for (const stage of ['queued', 'profiling']) {
      const source = ref<FeedItem[]>(structuredClone(mockFeed))
      const personalized = ref(true)
      const preview = useAnalysisPreview(source, personalized, stage)

      expect(preview.items.value).toEqual([])
      expect(preview.snapshot.value.hasAvailableResults).toBe(false)
      personalized.value = false
      expect(preview.items.value).toEqual(mockFeed)
      personalized.value = true
      expect(preview.items.value).toEqual([])
    }
  })

  it('falls back to completed for an unknown stage without changing source articles', () => {
    const source = ref<FeedItem[]>(structuredClone(mockFeed))
    const preview = useAnalysisPreview(source, ref(true), 'unknown-stage')

    expect(preview.stage.value).toBe('completed')
    expect(preview.items.value.map(item => item.id)).toEqual(mockFeed.map(item => item.id))
    expect(preview.snapshot.value.hasAvailableResults).toBe(true)
    expect(source.value).toEqual(mockFeed)
  })
})

it('keeps an explicitly unresolved historical result pending after its report is created', () => {
  const article = { ...structuredClone(mockFeed[0]!), id: 'history-pending', repositoryAnalysis: 'pending' as const }
  const preview = useAnalysisPreview(ref([article]), ref(true), 'completed')
  expect(preview.items.value[0]?.repositoryAnalysis).toBe('pending')
  expect(preview.pendingCount.value).toBe(1)
  expect(preview.analyzedCount.value).toBe(0)
})

it('does not infer a completed repository assessment from a known article or job completion', () => {
  const knownArticle = structuredClone(mockFeed[0]!)
  const unverifiedArticle: FeedItem = {
    ...knownArticle,
    id: 'submitted-unverified',
    assessment: 'unverified',
    repositoryAnalysis: 'analyzed',
  }
  const preview = useAnalysisPreview(ref([knownArticle, unverifiedArticle]), ref(true), 'completed')

  expect(preview.items.value.map(item => item.repositoryAnalysis)).toEqual(['pending', 'pending'])
  expect(preview.pendingCount.value).toBe(2)
  expect(preview.analyzedCount.value).toBe(0)
  expect(knownArticle.repositoryAnalysis).toBeUndefined()
})
