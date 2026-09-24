import { onScopeDispose, ref } from 'vue'

export type AppRoute =
  | { page: 'feed' | 'repositories' | 'saved' | 'settings' | 'analyze' }
  | { page: 'article'; articleId: string; repositoryUrl?: string }

export function readRoute(hash: string): AppRoute {
  try {
    const url = new URL(hash.replace(/^#/, '') || '/feed', 'https://local.invalid')
    const article = url.pathname.match(/^\/article\/([^/]+)$/)
    if (article) {
      return {
        page: 'article',
        articleId: decodeURIComponent(article[1]!),
        repositoryUrl: url.searchParams.get('repository') || undefined,
      }
    }
    const page = url.pathname.slice(1)
    if (page === 'repositories' || page === 'saved' || page === 'settings' || page === 'analyze') return { page }
  } catch {
    // A malformed deep link opens the feed.
  }
  return { page: 'feed' }
}

export function articlePath(id: string, repositoryUrl?: string): string {
  const params = repositoryUrl ? '?repository=' + encodeURIComponent(repositoryUrl) : ''
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
