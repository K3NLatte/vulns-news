export function createArticleShareUrl(currentUrl: string, articleId: string): string {
  const current = new URL(currentUrl)
  if (current.protocol !== 'https:' && current.protocol !== 'http:') {
    throw new TypeError('Article sharing requires an HTTP or HTTPS page.')
  }

  // Rebuild from the application location so account, repository and preview state stay private.
  const shared = new URL(current.origin)
  shared.pathname = current.pathname
  shared.hash = '/article/' + encodeURIComponent(articleId)
  return shared.href
}
