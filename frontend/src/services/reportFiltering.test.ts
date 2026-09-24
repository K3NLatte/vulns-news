import { describe, expect, it } from 'vitest'
import { filterFeedItems } from './feed'
import { createSubmittedReport } from './reports'
import { mockFeed } from '../mocks/feed'
import type { FeedQuery } from '../types/feed'

describe('unverified submission filtering', () => {
  const submitted = createSubmittedReport('CVE-2026-12345', 'cve', '2026-09-25T00:00:00.000Z')
  const query: FeedQuery = { scope: 'all', search: '', severity: 'all', sort: 'severity' }
  it('does not classify an unknown vulnerability as medium severity', () => {
    expect(filterFeedItems([submitted], { ...query, severity: 'medium' })).toEqual([])
    expect(filterFeedItems([submitted], query)).toEqual([submitted])
  })
  it('puts an unverified report after evaluated reports when ordering by severity', () => {
    expect(filterFeedItems([submitted, ...mockFeed], query).at(-1)?.id).toBe(submitted.id)
  })
})