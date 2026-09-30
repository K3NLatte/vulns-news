import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { parseFeedResult } from './feedContract'
import { filterFeedItems } from './feed'

// The Go integration test exports a validated real API response here on request.
const path = process.env.NEWS_TEST_FEED

describe.skipIf(!path)('existing analysis -> Go API -> frontend contract', () => {
  it('accepts all saved articles without fabricating confidence or exploitation', () => {
    const result = parseFeedResult(JSON.parse(readFileSync(path!, 'utf8')))
    expect(result.items.length).toBeGreaterThan(0)
    expect(result.items.length).toBe(result.total)
    for (const item of result.items) {
      expect(item.exploitation).toBe('unknown')
      expect(item.analysis.confidence).toBe('unknown')
      expect(item.relevance?.score).toBeUndefined()
    }
    expect(filterFeedItems(result.items, { scope: 'repository', search: '', severity: 'all', sort: 'newest' })).toHaveLength(result.total)
  })
})
