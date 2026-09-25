import { describe, expect, it } from 'vitest'
import { createWorkspaceStore } from './workspace'
import { mockFeed } from '../mocks/feed'
import {
  createReportLifecycle,
  createSubmittedReport,
  findExistingReport,
  historicalReports,
  isTrackingActive,
  normalizeReportInput,
  renewReportTracking,
  updateReportLifecycle,
} from './reports'

const now = '2026-09-25T12:00:00.000Z'

describe('report input', () => {
  it.each([
    [' cve-2025-10000 ', 'CVE-2025-10000', 'cve'],
    ['ghsa-jfh8-c2jp-5v3q', 'GHSA-JFH8-C2JP-5V3Q', 'ghsa'],
    ['HTTPS://EXAMPLE.ORG:443/advisory?id=123#details', 'https://example.org/advisory?id=123', 'url'],
  ])('normalizes %s without retrieving it', (input, key, kind) => {
    expect(normalizeReportInput(input)).toEqual({ ok: true, key, kind })
  })

  it.each([
    '', 'CVE-2026-123', 'GHSA-zzzz-zzzz-zzzz', 'x'.repeat(2_049),
    'javascript:alert(1)', 'http://example.org/report',
    'https://user:password@example.org/report', 'https://@example.org/report',
    'https://example.org:8443/report', 'https://localhost/report',
    'https://foo.local/report', 'https://127.0.0.1/report', 'https://2130706433/report',
    'https://[::1]/report', 'https://example.org/report\n',
    'https://example.org/report%0d%0aHeader:value', 'https://example.org/a b',
  ])('rejects unsupported input %s', (input) => {
    const result = normalizeReportInput(input)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.message.length).toBeGreaterThan(0)
  })

  it('reuses an exact advisory and its recognized source URL aliases', () => {
    const item = { ...mockFeed[0]!, advisoryId: 'CVE-2025-10000' }
    expect(findExistingReport('cve-2025-10000', [item])).toBe(item)
    expect(findExistingReport('https://nvd.nist.gov/vuln/detail/CVE-2025-10000', [item])).toBe(item)
    expect(findExistingReport('https://www.cve.org/CVERecord?id=CVE-2025-10000', [item])).toBe(item)
    expect(findExistingReport('https://attacker.example/CVE-2025-10000', [item])).toBeUndefined()
  })

  it('matches a canonical source URL while preserving its query semantics', () => {
    const item = historicalReports[0]!
    expect(findExistingReport(`${item.sources[0]!.url}#summary`, [item])).toBe(item)
    expect(findExistingReport(`${item.sources[0]!.url}?version=2`, [item])).toBeUndefined()
    expect(findExistingReport('CVE-2025-99999', [item])).toBeUndefined()
  })

  it('creates only an unverified submission without inventing vulnerability facts', () => {
    const item = createSubmittedReport('CVE-2025-10000', 'cve', now)
    expect(item.advisoryId).toBe('CVE-2025-10000')
    expect(item.cvss).toBeNull()
    expect(item.product).toBe('未確認')
    expect(item.affectedVersions).toBe('未確認')
    expect(item.fixedVersion).toBe('未確認')
    expect(item.repositoryAnalysis).toBe('pending')
    expect(item.remediation).toEqual([])
    expect(item.proofOfConcept).toBeUndefined()
    expect(item.relevance).toBeUndefined()
    expect(item.sources[0]!.url).toBe('https://nvd.nist.gov/vuln/detail/CVE-2025-10000')
    expect(item.id).toBe(createSubmittedReport('cve-2025-10000', 'cve', now).id)
  })

  it('uses a short opaque URL identifier without copying path or query metadata', () => {
    const input = 'https://example.org/advisories/private-review-name?ticket=TEAM-123&contact=person@example.org'
    const item = createSubmittedReport(input, 'url', now)
    expect(item.id).toMatch(/^submitted-url-[a-f0-9]{16}$/u)
    expect(item.id).not.toContain('private-review-name')
    expect(item.id).not.toContain('TEAM-123')
    expect(item.id).not.toContain('person')
    expect(item.id).not.toContain(encodeURIComponent(input))
    expect(item.id).toBe(createSubmittedReport(`${input}#details`, 'url', now).id)
    expect(item.id).not.toBe(createSubmittedReport(input.replace('TEAM-123', 'TEAM-124'), 'url', now).id)
    expect(item.id).not.toBe(createSubmittedReport(input.replace('private-review-name', 'other-advisory'), 'url', now).id)
    expect(item.sources[0]!.url).toBe(input)
  })

  it('keeps the public CVE and GHSA identifiers recognizable', () => {
    expect(createSubmittedReport('cve-2025-10000', 'cve', now).id).toBe('submitted-CVE-2025-10000')
    expect(createSubmittedReport('ghsa-jfh8-c2jp-5v3q', 'ghsa', now).id).toBe('submitted-GHSA-JFH8-C2JP-5V3Q')
  })
  it('does not allow the report factory to bypass input validation', () => {
    expect(() => createSubmittedReport('javascript:alert(1)', 'url', now)).toThrow()
    expect(() => createSubmittedReport('CVE-2025-10000', 'url', now)).toThrow()
    expect(() => createSubmittedReport('CVE-2025-10000', 'cve', 'invalid')).toThrow()
  })
})

describe('report tracking and revisions', () => {
  it('starts a submission without pretending an analysis already completed', () => {
    const item = createSubmittedReport('CVE-2025-10000', 'cve', now)
    const lifecycle = createReportLifecycle(item, now, 'submitted')
    expect(lifecycle).toMatchObject({ articleId: item.id, origin: 'submitted', revision: 0, lastAnalyzedAt: null, nextCheckAt: null, history: [] })
    expect(lifecycle.trackingUntil).toBe('2026-10-02T12:00:00.000Z')
    expect(updateReportLifecycle(lifecycle, now, 'scheduled')).toBe(lifecycle)
  })

  it('preserves an expired historical analysis for reuse without rescheduling it', () => {
    const lifecycle = createReportLifecycle(historicalReports[0]!, now, 'repository')
    expect(lifecycle.lastAnalyzedAt).toBe('2024-03-10T09:00:00.000Z')
    expect(lifecycle.revision).toBe(1)
    expect(lifecycle.nextCheckAt).toBeNull()
    expect(isTrackingActive(lifecycle, now)).toBe(false)
    expect(updateReportLifecycle(lifecycle, now, 'scheduled')).toBe(lifecycle)
  })

  it('runs only due updates inside the tracking window and does not mutate prior history', () => {
    const item = { ...mockFeed[0]!, updatedAt: '2026-09-24T12:00:00.000Z' }
    const lifecycle = createReportLifecycle(item, '2026-09-24T12:00:00.000Z')
    expect(updateReportLifecycle(lifecycle, '2026-09-25T11:59:59.000Z', 'scheduled')).toBe(lifecycle)
    const updated = updateReportLifecycle(lifecycle, now, 'scheduled')
    expect(updated.revision).toBe(2)
    expect(updated.history[1]).toEqual({ revision: 2, analyzedAt: now, reason: 'scheduled' })
    expect(updated.nextCheckAt).toBe('2026-09-26T12:00:00.000Z')
    expect(updated.trackingUntil).toBe(lifecycle.trackingUntil)
    expect(lifecycle.history).toHaveLength(1)
    expect(updateReportLifecycle(updated, now, 'scheduled')).toBe(updated)
  })

  it('stops at the exact tracking deadline', () => {
    const lifecycle = createReportLifecycle(mockFeed[0]!, now)
    expect(isTrackingActive(lifecycle, lifecycle.trackingUntil)).toBe(false)
    expect(updateReportLifecycle(lifecycle, lifecycle.trackingUntil, 'scheduled')).toBe(lifecycle)
  })

  it('allows manual analysis after expiry without silently renewing automatic tracking', () => {
    const lifecycle = createReportLifecycle(historicalReports[0]!, now, 'repository')
    const updated = updateReportLifecycle(lifecycle, now, 'manual')
    expect(updated.revision).toBe(2)
    expect(updated.lastAnalyzedAt).toBe(now)
    expect(updated.history[1]!.reason).toBe('manual')
    expect(updated.trackingUntil).toBe(lifecycle.trackingUntil)
    expect(updated.nextCheckAt).toBeNull()
    expect(isTrackingActive(updated, now)).toBe(false)
  })

  it('keeps renewal separate from analysis and guards against backwards timestamps', () => {
    const lifecycle = createReportLifecycle(historicalReports[0]!, now)
    const renewed = renewReportTracking(lifecycle, now)
    expect(renewed.trackingUntil).toBe('2026-10-02T12:00:00.000Z')
    expect(renewed.nextCheckAt).toBe('2026-09-26T12:00:00.000Z')
    expect(renewed.history).toEqual(lifecycle.history)
    expect(renewed.lastAnalyzedAt).toBe(lifecycle.lastAnalyzedAt)
    expect(updateReportLifecycle(lifecycle, '2024-03-09T00:00:00.000Z', 'manual')).toBe(lifecycle)
  })

  it('includes both reusable and unevaluated historical repository results', () => {
    expect(historicalReports.map((item) => item.repositoryAnalysis)).toEqual(['analyzed', 'pending'])
    expect(historicalReports.every((item) => item.relevance && item.publishedAt < '2025')).toBe(true)
    expect(historicalReports[1]!.cvss).toBeNull()
    expect(historicalReports[1]!.relevance!.score).toBeUndefined()
  })
})

it('keeps long accepted advisory IDs usable for saving, comments and review state', () => {
  const input = 'CVE-2026-' + '1'.repeat(200)
  const parsed = normalizeReportInput(input)
  expect(parsed.ok).toBe(true)
  const item = createSubmittedReport(input, 'cve', now)
  expect(item.advisoryId).toBe(input)
  expect(item.id.length).toBeLessThanOrEqual(200)
  expect(item.id).toBe(createSubmittedReport(input.toLowerCase(), 'cve', now).id)
  expect(item.id).not.toBe(createSubmittedReport(input + '2', 'cve', now).id)
  const store = createWorkspaceStore({ local: null, session: null })
  store.toggleSaved(item.id)
  store.addComment(item.id, '確認中')
  const repository = store.addRepository('https://github.com/example/project')
  if (!repository.ok) throw new Error(repository.message)
  store.setReviewStatus(repository.repository.id, item.id, 'investigating')
  expect(store.snapshot().savedIds).toEqual([item.id])
  expect(store.snapshot().comments[0]?.articleId).toBe(item.id)
  expect(store.getReviewStatus(repository.repository.id, item.id)).toBe('investigating')
})
