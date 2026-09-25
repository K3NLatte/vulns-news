import { describe, expect, it } from 'vitest'
import { mockFeed, repositoryFeedFor } from '../mocks/feed'
import { filterFeedItems } from './feed'
import { canReviewRepositoryArticle, resolveRepositoryArticle } from './repositoryAssessment'
import type { FeedItem, FeedQuery } from '../types/feed'

const query: FeedQuery = {
  scope: 'repository', repositoryUrl: 'https://github.com/example/backend',
  search: '', severity: 'all', sort: 'relevance',
}

describe('repository assessment boundaries', () => {
  it('does not reuse generic impact facts for an article absent from the selected repository', () => {
    const generic = mockFeed.find(item => item.id === 'demo-001')!
    const result = resolveRepositoryArticle(generic, repositoryFeedFor('example/backend'))!
    expect(result.id).toBe(generic.id)
    expect(result.relevance).toBeUndefined()
    expect(result.repositoryAnalysis).toBe('pending')
    expect(canReviewRepositoryArticle(result)).toBe(false)
    expect(generic.relevance?.score).toBe(74)
    expect(generic.repositoryAnalysis).toBeUndefined()
  })

  it('uses only the matching scoped assessment and keeps repository switches independent', () => {
    const generic = mockFeed.find(item => item.id === 'demo-002')!
    const backend = resolveRepositoryArticle(generic, repositoryFeedFor('example/backend'))!
    const frontend = resolveRepositoryArticle(generic, repositoryFeedFor('example/frontend'))!
    expect(backend.relevance?.score).toBe(95)
    expect(frontend.relevance?.score).toBe(92)
    expect(canReviewRepositoryArticle(backend)).toBe(true)
    expect(canReviewRepositoryArticle(frontend)).toBe(true)
    expect(backend.relevance?.score).toBe(95)
  })

  it('does not allow a decision on pending, unverified, or missing repository assessments', () => {
    const article = structuredClone(mockFeed[0]!)
    const pending = { ...article, repositoryAnalysis: 'pending' as const }
    const unverified = { ...article, repositoryAnalysis: 'analyzed' as const, assessment: 'unverified' as const }
    for (const value of [article, pending, unverified, { ...article, repositoryAnalysis: 'analyzed' as const, relevance: undefined }]) {
      expect(canReviewRepositoryArticle(value)).toBe(false)
    }
    expect(resolveRepositoryArticle(unverified, [unverified])?.repositoryAnalysis).toBe('pending')
    expect(resolveRepositoryArticle(null, [])).toBeNull()
    expect(canReviewRepositoryArticle(null)).toBe(false)
  })

  it('sorts classified pending repository candidates after evaluated scores', () => {
    const items = filterFeedItems(repositoryFeedFor('example/backend'), query)
    expect(items.map(item => item.id)).toEqual(['demo-002', 'demo-004', 'demo-007', 'demo-005', 'demo-009'])
    expect(items.find(item => item.id === 'demo-005')?.repositoryAnalysis).toBe('pending')
  })

  it('ignores a hidden score even if an adapter supplies it on a pending or unverified result', () => {
    const base = structuredClone(mockFeed[0]!)
    const items: FeedItem[] = [
      { ...base, id: 'pending', repositoryAnalysis: 'pending', relevance: { ...base.relevance!, score: 100 } },
      { ...base, id: 'unverified', assessment: 'unverified', relevance: { ...base.relevance!, score: 99 } },
      { ...base, id: 'evaluated', repositoryAnalysis: 'analyzed', relevance: { ...base.relevance!, score: 1 } },
    ]
    expect(filterFeedItems(items, query)[0]?.id).toBe('evaluated')
    expect(items[0]?.relevance?.score).toBe(100)
  })
})
