import { describe, expect, it } from 'vitest'
import { createArticleShareUrl } from './sharing'

describe('article sharing URLs', () => {
  it('shares only the article route, excluding repository, account and preview state', () => {
    const shared = createArticleShareUrl(
      'https://feed.example/app/?repository=private%2Frepo&user=alice&view=mvp&analysis=failed#/repositories?sort=relevance',
      'ADV-008',
    )

    expect(shared).toBe('https://feed.example/app/#/article/ADV-008')
  })

  it('encodes an article ID so it cannot inject a route or query parameters', () => {
    const shared = createArticleShareUrl(
      'https://feed.example/',
      '../analysis?repository=secret#token/日本語',
    )
    const url = new URL(shared)

    expect(url.origin).toBe('https://feed.example')
    expect(url.search).toBe('')
    expect(url.hash).toBe('#/article/..%2Fanalysis%3Frepository%3Dsecret%23token%2F%E6%97%A5%E6%9C%AC%E8%AA%9E')
  })

  it('preserves the application path and development port without leaking URL credentials', () => {
    expect(createArticleShareUrl('http://user:password@localhost:5173/app/?session=secret', 'CVE-2026-1234'))
      .toBe('http://localhost:5173/app/#/article/CVE-2026-1234')
  })

  it('does not reinterpret an application pathname starting with two slashes as another origin', () => {
    const shared = createArticleShareUrl('https://feed.example//other.example/app/', 'report')
    expect(new URL(shared).origin).toBe('https://feed.example')
  })

  it.each(['javascript:alert(1)', 'file:///tmp/report.html', 'data:text/html,report'])(
    'does not produce a share link for non-web locations: %s',
    location => {
      expect(() => createArticleShareUrl(location, 'report')).toThrow(TypeError)
    },
  )
})
