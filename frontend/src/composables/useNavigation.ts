import { onScopeDispose, ref } from 'vue'
import { parseRepositoryUrl } from '../utils/repositoryUrl'
import { isWellFormedText } from '../utils/publicUrl'

export type AppRoute =
  | { page: 'feed' | 'repositories' | 'saved' | 'settings' | 'analyze' }
  | { page: 'not-found' }
  | { page: 'article'; articleId: string; repositoryUrl?: string }

function validArticleId(id: string): boolean {
  return (
    id !== '.' &&
    id !== '..' &&
    id.length > 0 &&
    id.length <= 200 &&
    isWellFormedText(id) &&
    !/[\s\u0000-\u001f\u007f]/u.test(id)
  )
}
export function readRoute(hash: string): AppRoute {
  if (!hash || hash === '#/' || hash === '#/feed') return { page: 'feed' }
  try {
    if (!hash.startsWith('#/') || hash.startsWith('#//') || hash.length > 8000) return { page: 'not-found' }
    const url = new URL(hash.slice(1), 'https://local.invalid')
    if (url.origin !== 'https://local.invalid') return { page: 'not-found' }
    const article = url.pathname.match(/^\/article\/([^/]+)$/u)
    if (article) {
      const articleId = decodeURIComponent(article[1]!)
      if (!validArticleId(articleId)) return { page: 'not-found' }
      const repository = parseRepositoryUrl(url.searchParams.get('repository'))
      return { page: 'article', articleId, repositoryUrl: repository.ok ? repository.url : undefined }
    }
    const page = url.pathname.slice(1)
    if (page === 'feed' || page === 'repositories' || page === 'saved' || page === 'settings' || page === 'analyze')
      return { page }
  } catch {
    // Preserve the invalid location and render a recoverable not-found page.
  }
  return { page: 'not-found' }
}

export function articlePath(id: string, repositoryUrl?: string): string {
  if (!validArticleId(id)) return '#/feed'
  const repository = parseRepositoryUrl(repositoryUrl)
  const params = repository.ok ? '?repository=' + encodeURIComponent(repository.url) : ''
  return '#/article/' + encodeURIComponent(id) + params
}

interface NavigationEntry {
  id: string
  hash: string
  from?: string
}
let sequence = 0
export function useNavigation() {
  function entry(from?: string): NavigationEntry {
    const hash = window.location.hash || '#/feed'
    const existing = window.history.state?.vulnsNavigation as NavigationEntry | undefined
    if (existing?.hash === hash && typeof existing.id === 'string') return existing
    const created = { id: Date.now() + '-' + ++sequence, hash, from }
    window.history.replaceState({ ...window.history.state, vulnsNavigation: created }, '', window.location.href)
    return created
  }
  let current = entry()
  const route = ref<AppRoute>(readRoute(current.hash))
  const entryId = ref(current.id)
  function syncRoute() {
    const next = entry(current.hash)
    if (next.id === current.id) return
    current = next
    route.value = readRoute(current.hash)
    entryId.value = current.id
  }
  window.addEventListener('hashchange', syncRoute)
  window.addEventListener('popstate', syncRoute)
  onScopeDispose(() => {
    window.removeEventListener('hashchange', syncRoute)
    window.removeEventListener('popstate', syncRoute)
  })
  function navigate(hash: string, replace = false) {
    if (hash === current.hash) return
    const next: NavigationEntry = {
      id: Date.now() + '-' + ++sequence,
      hash,
      from: replace ? current.from : current.hash,
    }
    window.history[replace ? 'replaceState' : 'pushState']({ ...window.history.state, vulnsNavigation: next }, '', hash)
    syncRoute()
  }
  function backTo(fallback: string) {
    if (current.from === fallback) window.history.back()
    else navigate(fallback, true)
  }
  return { route, entryId, navigate, backTo }
}
