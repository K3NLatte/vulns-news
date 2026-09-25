import { describe, expect, it } from 'vitest'
import { articlePath, readRoute } from './useNavigation'

describe('article deep links', () => {
  it('round-trips repository context using the same canonical URL as saved settings', () => {
    const path = articlePath('demo-006', 'https://github.com/Example/Project.git/')
    expect(readRoute(path)).toEqual({ page: 'article', articleId: 'demo-006', repositoryUrl: 'https://github.com/example/project' })
  })
  it.each(['', '#unknown', '#/unknown', '#https://evil.example/article/demo-001', '#//evil.example/article/demo-001', '#/article/%E0%A4%A', '#/article/%00', '#/article/' + 'x'.repeat(201)])('falls back for malformed local routes: %s', hash => {
    expect(readRoute(hash)).toEqual({ page: 'feed' })
  })
  it('drops unsupported repository context without sending it into a request', () => {
    expect(readRoute('#/article/demo-006?repository=https://evil.example/foo')).toEqual({ page: 'article', articleId: 'demo-006', repositoryUrl: undefined })
  })
  it('does not throw when asked to share a malformed identifier', () => {
    expect(articlePath(String.fromCharCode(0xd800))).toBe('#/feed')
  })
})
