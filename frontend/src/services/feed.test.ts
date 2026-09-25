import { describe, expect, it, vi } from 'vitest'
import { getFeed, parseRepositoryUrl } from './feed'
import { mockFeed } from '../mocks/feed'
import type { FeedQuery } from './feed'

const allFeed: FeedQuery = {
  scope: 'all',
  search: '',
  severity: 'all',
  sort: 'newest',
}

const load = (overrides: Partial<FeedQuery> = {}) => getFeed({ ...allFeed, ...overrides }, { delayMs: 0 })

describe('parseRepositoryUrl', () => {
  it.each([
    ['https://github.com/example/project', 'https://github.com/example/project', 'example/project'],
    ['  https://github.com/Example/project.git/  ', 'https://github.com/example/project', 'Example/project'],
    ['HTTPS://GITHUB.COM/example/project/', 'https://github.com/example/project', 'example/project'],
    ['https://github.com:443/example/project', 'https://github.com/example/project', 'example/project'],
    ['https://github.com/example-org/project_name.js', 'https://github.com/example-org/project_name.js', 'example-org/project_name.js'],
  ])('normalizes a repository URL: %s', (input, url, label) => {
    expect(parseRepositoryUrl(input)).toEqual({ ok: true, url, label })
  })

  it.each([
    '',
    'not a URL',
    'github.com/example/project',
    'http://github.com/example/project',
    'javascript:alert(1)',
    'https://gitlab.com/example/project',
    'https://github.com.evil.example/example/project',
    'https://evil.github.com/example/project',
    'https://user:secret@github.com/example/project',
    'https://github.com@evil.example/example/project',
    'https://@github.com/example/project',
    'https://github.com:8443/example/project',
    'https://github.com/example',
    'https://github.com/example/project/tree/main',
    'https://github.com/example/project/blob/main/README.md',
    'https://github.com/example/project?tab=readme',
    'https://github.com/example/project?',
    'https://github.com/example/project#readme',
    'https://github.com/example/project#',
    'https://github.com/example/%70roject',
    'https://github.com/example/project%2Ftree',
    'https://github.com/example//project',
    'https://github.com/example/./project',
    'https://github.com/example/project/../project',
    'https://github.com/example/.git',
    'https://github.com/example/..',
    'https://github.com/example/project name',
    'https://github.com/example\\project',
  ])('rejects unsupported or misleading URLs: %s', (input) => {
    const result = parseRepositoryUrl(input)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.message.length).toBeGreaterThan(0)
  })
})

describe('getFeed', () => {
  it('returns the general feed without contacting a server', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    try {
      const result = await load()
      expect(result.items).toHaveLength(12)
      expect(result.total).toBe(12)
      expect(result.matchedTotal).toBe(12)
      expect(result.generatedAt).toBe('2026-09-24T03:00:00.000Z')
      expect(fetchSpy).not.toHaveBeenCalled()
    } finally {
      fetchSpy.mockRestore()
    }
  })

  it('sorts publication times newest first', async () => {
    const result = await load()
    expect(result.items[0]?.advisoryId).toBe('DEMO-2026-001')
    expect(result.items.at(-1)?.advisoryId).toBe('DEMO-2026-012')
    const times = result.items.map((item) => item.publishedAt)
    expect(times).toEqual([...times].sort().reverse())
  })

  it('sorts severity band, CVSS score and then publication time', async () => {
    const result = await load({ sort: 'severity' })
    expect(result.items.map((item) => item.advisoryId)).toEqual([
      'DEMO-2026-001', 'DEMO-2026-004', 'DEMO-2026-009',
      'DEMO-2026-003', 'DEMO-2026-005', 'DEMO-2026-002', 'DEMO-2026-007', 'DEMO-2026-011',
      'DEMO-2026-006', 'DEMO-2026-008', 'DEMO-2026-010', 'DEMO-2026-012',
    ])
  })

  it('sorts repository results by their explicit relevance scores', async () => {
    const result = await load({
      scope: 'repository',
      repositoryUrl: 'https://github.com/example/project',
      sort: 'relevance',
    })
    expect(result.items.map((item) => item.id)).toEqual([
      'demo-003', 'demo-002', 'demo-006', 'demo-001', 'demo-008', 'demo-005',
    ])
    expect(result.items.map((item) => item.relevance?.score)).toEqual([98, 92, 86, 74, 68, undefined])
    expect(result.total).toBe(6)
    expect(result.matchedTotal).toBe(6)
  })

  it('uses publication time and ID for tied scores and puts unscored results last', async () => {
    const originalItems = mockFeed.slice()
    const example = mockFeed.find((item) => item.relevance)!
    const cases = [
      { id: 'unscored', score: undefined, publishedAt: '2026-09-24T03:00:00.000Z' },
      { id: 'infinite', score: Number.POSITIVE_INFINITY, publishedAt: '2026-09-24T02:00:00.000Z' },
      { id: 'nan', score: Number.NaN, publishedAt: '2026-09-24T01:00:00.000Z' },
      { id: 'negative-infinite', score: Number.NEGATIVE_INFINITY, publishedAt: '2026-09-24T00:00:00.000Z' },
      { id: 'zero', score: 0, publishedAt: '2026-09-20T00:00:00.000Z' },
      { id: 'score-b', score: 50, publishedAt: '2026-09-23T00:00:00.000Z' },
      { id: 'score-older', score: 50, publishedAt: '2026-09-22T00:00:00.000Z' },
      { id: 'score-a', score: 50, publishedAt: '2026-09-23T00:00:00.000Z' },
    ]
    const fixtures = cases.map(({ id, score, publishedAt }) => ({
      ...structuredClone(example),
      id,
      publishedAt,
      relevance: { ...example.relevance!, score },
    }))
    try {
      mockFeed.splice(0, mockFeed.length, ...fixtures)
      const result = await load({
        scope: 'repository',
        repositoryUrl: 'https://github.com/example/project',
        sort: 'relevance',
      })
      expect(result.items.map((item) => item.id)).toEqual([
        'score-a', 'score-b', 'score-older', 'zero',
        'unscored', 'infinite', 'nan', 'negative-infinite',
      ])
    } finally {
      mockFeed.splice(0, mockFeed.length, ...originalItems)
    }
  })

  it('combines repository relevance sorting with search and severity filters', async () => {
    const result = await load({
      scope: 'repository',
      repositoryUrl: 'https://github.com/example/project',
      sort: 'relevance',
      severity: 'high',
      search: 'DEMO-2026',
    })
    expect(result.items.map((item) => item.id)).toEqual(['demo-003', 'demo-002', 'demo-005'])
    expect(result.total).toBe(6)
    expect(result.matchedTotal).toBe(3)
    const narrowed = await load({
      scope: 'repository',
      repositoryUrl: 'https://github.com/example/project',
      sort: 'relevance',
      severity: 'high',
      search: 'TrialAttachment',
    })
    expect(narrowed.items.map((item) => item.id)).toEqual(['demo-003'])
    expect(narrowed.total).toBe(6)
    expect(narrowed.matchedTotal).toBe(1)
  })

  it('falls back to newest order for relevance sorting outside repository scope', async () => {
    const newest = await load({ sort: 'newest' })
    const relevance = await load({ sort: 'relevance', repositoryUrl: 'https://github.com/example/project' })
    expect(relevance.items.map((item) => item.id)).toEqual(newest.items.map((item) => item.id))
    expect(relevance.total).toBe(12)
  })

  it('keeps the scope total separate from the filtered count', async () => {
    const result = await load({ severity: 'high' })
    expect(result.total).toBe(12)
    expect(result.matchedTotal).toBe(5)
    expect(result.items).toHaveLength(5)
    expect(result.items.every((item) => item.severity === 'high')).toBe(true)
  })

  it('matches full-width and case-insensitive search terms', async () => {
    const result = await load({ search: '  ｄｅｍｏｍａｒｋｄｏｗｎ  ' })
    expect(result.items.map((item) => item.advisoryId)).toEqual(['DEMO-2026-006'])
  })

  it('requires all search words and combines search with severity', async () => {
    const matching = await load({ search: 'sampleview テンプレート', severity: 'critical' })
    const excluded = await load({ search: 'sampleview テンプレート', severity: 'low' })
    const unrelated = await load({ search: 'sampleview SQL' })
    expect(matching.items.map((item) => item.id)).toEqual(['demo-001'])
    expect(excluded.matchedTotal).toBe(0)
    expect(unrelated.matchedTotal).toBe(0)
  })

  it('searches advisory IDs and component names', async () => {
    const byId = await load({ search: 'demo-2026-010' })
    const byComponent = await load({ search: 'recursive decoder' })
    expect(byId.items.map((item) => item.id)).toEqual(['demo-010'])
    expect(byComponent.items.map((item) => item.id)).toEqual(['demo-008'])
  })

  it('returns only sample dependency matches in repository scope', async () => {
    const result = await load({ scope: 'repository', repositoryUrl: 'https://github.com/example/project' })
    expect(result.total).toBe(6)
    expect(result.matchedTotal).toBe(6)
    expect(result.items.every((item) => item.relevance !== undefined)).toBe(true)
    const highOnly = await load({ scope: 'repository', repositoryUrl: 'https://github.com/example/project', severity: 'high' })
    expect(highOnly.total).toBe(6)
    expect(highOnly.matchedTotal).toBe(3)
  })

  it('returns deterministic results for equivalent repository URLs', async () => {
    const first = await load({ scope: 'repository', repositoryUrl: 'https://github.com/Example/Frontend.git' })
    const second = await load({ scope: 'repository', repositoryUrl: 'https://github.com/example/frontend/' })
    expect(first).toEqual(second)
  })

  it('changes matches and review priorities when the active repository profile changes', async () => {
    const frontend = await load({ scope: 'repository', repositoryUrl: 'https://github.com/example/frontend', sort: 'relevance' })
    const backend = await load({ scope: 'repository', repositoryUrl: 'https://github.com/example/backend', sort: 'relevance' })
    const tooling = await load({ scope: 'repository', repositoryUrl: 'https://github.com/example/tooling', sort: 'relevance' })
    expect([frontend.total, backend.total, tooling.total]).toEqual([6, 5, 4])
    expect(frontend.items.map(item => item.id)).not.toEqual(backend.items.map(item => item.id))
    expect(tooling.items[0]?.id).toBe('demo-008')
    expect(tooling.items[0]?.severity).toBe('medium')
    expect(tooling.items[0]?.relevance?.priority).toBe('urgent')
    expect(frontend.items.find(item => item.id === 'demo-008')?.relevance?.priority).toBe('medium')
    expect(backend.items.find(item => item.id === 'demo-005')?.relevance?.priority).toBe('review')
    expect(frontend.items.find(item => item.id === 'demo-005')?.relevance?.priority).toBe('review')
  })

  it('requires a valid repository URL before entering repository scope', async () => {
    await expect(load({ scope: 'repository' })).rejects.toThrow('URLを入力')
    await expect(load({ scope: 'repository', repositoryUrl: 'https://evil.example/a/b' })).rejects.toThrow('github.com')
  })

  it('returns an ordinary empty result for no matching search', async () => {
    const result = await load({ search: '存在しないサンプル製品' })
    expect(result.items).toEqual([])
    expect(result.total).toBe(12)
    expect(result.matchedTotal).toBe(0)
  })

  it('supports the empty preview scenario', async () => {
    const result = await getFeed(allFeed, { scenario: 'empty', delayMs: 0 })
    expect(result.items).toEqual([])
    expect(result.total).toBe(0)
    expect(result.matchedTotal).toBe(0)
  })

  it('rejects the error scenario so a view can offer retry', async () => {
    await expect(getFeed(allFeed, { scenario: 'error', delayMs: 0 })).rejects.toThrow('再試行')
    expect((await load()).items).toHaveLength(12)
  })

  it('cancels before starting a request', async () => {
    const controller = new AbortController()
    controller.abort()
    await expect(getFeed(allFeed, { signal: controller.signal, delayMs: 0 })).rejects.toMatchObject({ name: 'AbortError' })
  })

  it('cancels during a request rather than resolving stale results', async () => {
    const controller = new AbortController()
    const request = getFeed(allFeed, { signal: controller.signal, delayMs: 10_000 })
    const rejected = expect(request).rejects.toMatchObject({ name: 'AbortError' })
    controller.abort()
    await rejected
  })

  it('returns independent response objects', async () => {
    const first = await load()
    const originalTitle = first.items[0]!.title
    const originalSummary = first.items[0]!.analysis.summary
    first.items[0]!.title = 'view-local change'
    first.items[0]!.analysis.summary = 'view-local analysis'
    first.items[0]!.sources.length = 0
    const second = await load()
    expect(second.items[0]!.title).toBe(originalTitle)
    expect(second.items[0]!.analysis.summary).toBe(originalSummary)
    expect(second.items[0]!.sources).toHaveLength(1)
  })

  it('keeps fictional advisories distinct from general security references', async () => {
    const result = await load()
    expect(result.items.every((item) => item.advisoryId.startsWith('DEMO-'))).toBe(true)
    expect(result.items.every((item) => item.sources.every((source) => source.kind === 'reference' && source.url.startsWith('https://cwe.mitre.org/')))).toBe(true)
    expect(result.items.some((item) => item.cvss === null)).toBe(true)
  })
})

it('rejects oversized and malformed repository values without throwing', () => {
  for (const input of [null, {}, ['https://github.com/example/project'], 'https://github.com/example/' + 'x'.repeat(2048), '\u0000https://github.com/example/project', '\ud800']) {
    expect(parseRepositoryUrl(input).ok).toBe(false)
  }
})

it('keeps unscored CVSS out of low severity and supports an explicit unknown filter', async () => {
  const unknown = await getFeed({ scope: 'all', search: '', sort: 'severity', severity: 'unknown' }, { delayMs: 0 })
  expect(unknown.items.map(item => item.id)).toEqual(['demo-012'])
  const low = await getFeed({ scope: 'all', search: '', sort: 'severity', severity: 'low' }, { delayMs: 0 })
  expect(low.items.map(item => item.id)).not.toContain('demo-012')
})
it('rejects reserved GitHub paths and overlong names', () => {
  for (const url of ['https://github.com/features/actions', 'https://github.com/' + 'a'.repeat(40) + '/repo', 'https://github.com/owner/' + 'r'.repeat(101)]) {
    expect(parseRepositoryUrl(url).ok).toBe(false)
  }
})
