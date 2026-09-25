/* eslint-disable @typescript-eslint/no-explicit-any -- These mutations deliberately violate each runtime boundary to test untrusted responses. */
import { describe, expect, it } from 'vitest'
import { getFeed } from './feed'
import { parseFeedResult } from './feedContract'
import { createSubmittedReport } from './reports'

const fixture = () => getFeed({ scope: 'all', search: '', severity: 'all', sort: 'newest' }, { delayMs: 0 })
describe('feed adapter boundary', () => {
  it('returns independent validated view data while Vue escapes ordinary markup', async () => {
    const input = await fixture()
    input.items[0]!.title = '<img src=x onerror=alert(1)>'
    const result = parseFeedResult(input)
    expect(result).toEqual(input)
    result.items[0]!.title = '変更'
    expect(input.items[0]!.title).not.toBe('変更')
  })
  it.each([
    ['missing summary', (data: any) => delete data.items[0].summary],
    ['invalid date', (data: any) => data.items[0].publishedAt = '2026-02-30T00:00:00.000Z'],
    ['unknown severity', (data: any) => data.items[0].severity = 'fatal'],
    ['NaN score', (data: any) => data.items[0].cvss = NaN],
    ['out-of-range CVSS', (data: any) => data.items[0].cvss = 11],
    ['inconsistent CVSS band', (data: any) => data.items[0].severity = 'low'],
    ['duplicate IDs', (data: any) => data.items[1].id = data.items[0].id],
    ['malformed unicode', (data: any) => data.items[0].title = String.fromCharCode(0xd800)],
    ['bidi identifier', (data: any) => data.items[0].advisoryId += '\u202e'],
    ['invisible title', (data: any) => data.items[0].title = '\u200b'],
    ['out-of-range relevance', (data: any) => data.items[0].relevance.score = 101],
    ['untrusted source URL', (data: any) => data.items[0].sources[0].url = 'javascript:alert(1)'],
    ['pending definitive score', (data: any) => data.items[0].repositoryAnalysis = 'pending'],
  ])('quarantines %s without discarding the other rows', async (_, change) => {
    const input = await fixture()
    change(input)
    const parsed = parseFeedResult(input)
    expect(parsed.items).toHaveLength(input.items.length - 1)
    expect(parsed.rejectedCount).toBe(1)
  })
  it.each([
    ['non-array', (data: any) => data.items = null],
    ['inconsistent total', (data: any) => data.total = 0],
    ['fewer matches than page', (data: any) => data.matchedTotal = 0],
    ['oversized page', (data: any) => data.items = Array(1001).fill(data.items[0])],
    ['oversized response', (data: any) => data.extra = 'x'.repeat(2_000_000)],
  ])('rejects an invalid envelope: %s', async (_, change) => {
    const input = await fixture()
    change(input)
    expect(() => parseFeedResult(input)).toThrow('データ形式')
  })
  it('represents an unknown advisory without inventing score, confidence or dates', () => {
    const item = createSubmittedReport('CVE-2026-12345', 'cve', '2026-09-25T00:00:00.000Z')
    const parsed = parseFeedResult({ items: [item], total: 1, matchedTotal: 1, generatedAt: '2026-09-25T00:00:00.000Z' })
    expect(parsed.items).toEqual([item])
    expect(parsed.items[0]).toMatchObject({ cvss: null, severity: 'unknown', publishedAt: null, updatedAt: null, analysis: { confidence: 'unknown' } })
  })
  it('rejects definitive relevance on an unverified advisory without a repository state', async () => {
    const input = await fixture()
    const item = createSubmittedReport('CVE-2026-12345', 'cve', '2026-09-25T00:00:00.000Z')
    item.relevance = input.items[0]!.relevance
    delete item.repositoryAnalysis
    const parsed = parseFeedResult({ items: [item], total: 1, matchedTotal: 1, generatedAt: input.generatedAt })
    expect(parsed).toMatchObject({ items: [], rejectedCount: 1 })
  })
  it('accepts totals larger than one page and preserves the opaque cursor', async () => {
    const input = await fixture()
    const result = parseFeedResult({ ...input, total: 10_000, matchedTotal: 7000, nextCursor: 'page:2' })
    expect(result).toMatchObject({ total: 10_000, matchedTotal: 7000, nextCursor: 'page:2' })
  })
  it('requires an adapter allowlist before describing a source as the vendor', async () => {
    const input = await fixture()
    input.items[0]!.sources = [{ name: '製品の提供元', url: 'https://evil.example/advisory', kind: 'vendor' }]
    expect(parseFeedResult(input).items[0]?.sources[0]?.kind).toBe('reference')
    expect(parseFeedResult(input, new Set(['evil.example'])).items[0]?.sources[0]?.kind).toBe('vendor')
  })
  it('rejects the current raw Go CVE shape instead of inventing scores or dates', () => {
    expect(() => parseFeedResult([{ id: 'CVE-2026-12345', description: '説明' }])).toThrow('データ形式')
  })
})

it('distinguishes zero CVSS from unscored and low values', async () => {
  const input = await fixture()
  input.items = [{ ...input.items[0]!, cvss: 0, severity: 'none' }]
  input.total = 1
  input.matchedTotal = 1
  expect(parseFeedResult(input).items[0]?.severity).toBe('none')
  input.items[0]!.severity = 'low'
  expect(parseFeedResult(input)).toMatchObject({ items: [], rejectedCount: 1 })
})

it('normalizes CRLF prose and accepts explicitly unavailable vulnerability facts', async () => {
  const input = await fixture()
  input.items[0]!.summary = '段落1\r\n段落2'
  input.items[0]!.fixedVersion = null
  const result = parseFeedResult(input)
  expect(result.items[0]?.summary).toBe('段落1\n段落2')
  expect(result.items[0]?.fixedVersion).toBeNull()
  expect(result.rejectedCount).toBeUndefined()
})
