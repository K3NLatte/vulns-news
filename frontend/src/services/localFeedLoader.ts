import { getFeed, filterFeedItems } from './feed'
import type { FeedLoader } from './feedContract'
import type { FeedItem } from '../types/feed'

/** Local-only composition. Replace this adapter as a whole when connecting a server feed. */
export function createLocalFeedLoader(
  local: (repositoryUrl: string) => { additions: FeedItem[]; savedItems?: FeedItem[]; savedIds?: readonly string[] },
): FeedLoader {
  return async (query, options) => {
    const response = await getFeed({ ...query, search: '', severity: 'all' }, options)
    if (options.scenario === 'empty') return response
    const state = local(query.repositoryUrl ?? '')
    const unique = [
      ...new Map(
        [...(state.savedItems ?? []), ...response.items, ...state.additions].map((item) => [item.id, item]),
      ).values(),
    ]
    const source = state.savedIds ? unique.filter((item) => state.savedIds!.includes(item.id)) : unique
    const items = filterFeedItems(source, query)
    return { ...response, items, total: source.length, matchedTotal: items.length }
  }
}
