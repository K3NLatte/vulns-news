import type { FeedItem } from '../types/feed'

/** An article may be known while its assessment for the current repository is not. */
export function resolveRepositoryArticle(
  article: FeedItem | null,
  scopedItems: readonly FeedItem[],
): FeedItem | null {
  if (!article) return null
  const scoped = scopedItems.find(item => item.id === article.id)
  if (scoped) {
    return {
      ...scoped,
      repositoryAnalysis: scoped.repositoryAnalysis === 'analyzed' && scoped.assessment !== 'unverified'
        ? 'analyzed' : 'pending',
    }
  }
  const unresolved: FeedItem = { ...article, repositoryAnalysis: 'pending' }
  delete unresolved.relevance
  return unresolved
}

/** Editing a decision requires an available assessment for the selected repository. */
export function canReviewRepositoryArticle(item: FeedItem | null): boolean {
  return Boolean(item && item.repositoryAnalysis === 'analyzed'
    && item.assessment !== 'unverified' && item.relevance)
}
