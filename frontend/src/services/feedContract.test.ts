import { describe, expect, it } from 'vitest'
import { getFeed } from './feed'
import { parseFeedResult } from './feedContract'

const fixture = () => getFeed({ scope: 'all', search: '', severity: 'all', sort: 'newest' }, { delayMs: 0 })
describe('feed adapter boundary', () => {
  it('returns independent, validated view data without stripping text that must be escaped by Vue', async () => {
    const input = await fixture()
    input.items[0]!.title = '<img src=x onerror=alert(1)>'
    const result = parseFeedResult(input)
    expect(result).toEqual(input)
    result.items[0]!.title = '変更'
    expect(input.items[0]!.title).not.toBe('変更')
  })
  it.each([
    ['non-object', (data: any) => data.items = null],
    ['missing summary', (data: any) => delete data.items[0].summary],
    ['invalid date', (data: any) => data.items[0].publishedAt = '2026-02-30T00:00:00.000Z'],
    ['unknown severity', (data: any) => data.items[0].severity = 'fatal'],
    ['NaN score', (data: any) => data.items[0].cvss = NaN],
    ['out-of-range CVSS', (data: any) => data.items[0].cvss = 11],
    ['duplicate IDs', (data: any) => data.items[1].id = data.items[0].id],
    ['inconsistent total', (data: any) => data.total = 0],
    ['partial count', (data: any) => data.matchedTotal = 100],
    ['oversized page', (data: any) => data.items = Array(1001).fill(data.items[0])],
    ['malformed unicode', (data: any) => data.items[0].title = String.fromCharCode(0xd800)],
    ['out-of-range relevance', (data: any) => data.items.find((item: any) => item.relevance).relevance.score = 101],
  ])('rejects %s without returning partially trusted content', async (_, change) => {
    const input = await fixture()
    change(input)
    expect(() => parseFeedResult(input)).toThrow('データ形式')
  })
  it('rejects the current raw Go CVE shape rather than inventing scores or dates', () => {
    expect(() => parseFeedResult([{ id: 'CVE-2026-12345', description: '説明' }])).toThrow('データ形式')
  })
})
