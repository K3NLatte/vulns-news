import { onScopeDispose, ref } from 'vue'
import { parseRepositoryUrl } from '../services/feed'
import { isWellFormedText } from '../utils/publicUrl'

export type AppRoute =
  | { page: 'feed' | 'repositories' | 'saved' | 'settings' | 'analyze' }
  | { page: 'article'; articleId: string; repositoryUrl?: string }

function validArticleId(id: string): boolean {
  return id.length > 0 && id.length <= 200 && isWellFormedText(id) && !/[\s\u0000-\u001f\u007f]/u.test(id)
}
export function readRoute(hash: string): AppRoute {
  try {
    if (!hash.startsWith('#/') || hash.startsWith('#//') || hash.length > 8000) return { page: 'feed' }
    const url = new URL(hash.slice(1), 'https://local.invalid')
    if (url.origin !== 'https://local.invalid') return { page: 'feed' }
    const article = url.pathname.match(/^\/article\/([^/]+)$/u)
    if (article) {
      const articleId = decodeURIComponent(article[1]!)
      if (!validArticleId(articleId)) return { page: 'feed' }
      const repository = parseRepositoryUrl(url.searchParams.get('repository'))
      return { page: 'article', articleId, repositoryUrl: repository.ok ? repository.url : undefined }
    }
    const page = url.pathname.slice(1)
    if (page === 'repositories' || page === 'saved' || page === 'settings' || page === 'analyze') return { page }
  } catch {
    // A malformed deep link opens the feed.
  }
  return { page: 'feed' }
}

export function articlePath(id: string, repositoryUrl?: string): string {
  if (!validArticleId(id)) return '#/feed'
  const repository = parseRepositoryUrl(repositoryUrl)
  const params = repository.ok ? '?repository=' + encodeURIComponent(repository.url) : ''
  return '#/article/' + encodeURIComponent(id) + params
}

export function useNavigation() {
  const route = ref<AppRoute>(readRoute(window.location.hash))
  function syncRoute() { route.value = readRoute(window.location.hash) }
  window.addEventListener('hashchange', syncRoute)
  onScopeDispose(() => window.removeEventListener('hashchange', syncRoute))
  function navigate(hash: string) { window.location.hash = hash }
  return { route, navigate }
}
