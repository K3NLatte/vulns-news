import { describe, expect, it } from 'vitest'
import { dateTime, fullDate, safeExternalUrl, shortDate } from './presentation'

describe('reference URL safety', () => {
  it('allows HTTPS references', () => {
    expect(safeExternalUrl('https://cwe.mitre.org/data/definitions/94.html'))
      .toBe('https://cwe.mitre.org/data/definitions/94.html')
  })
  it.each([
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'http://example.com',
    '//example.com',
    'not a url',
    'https://user:password@example.com',
  ])('does not turn unsafe or ambiguous references into links: %s', value => {
    expect(safeExternalUrl(value)).toBeUndefined()
  })
})

it('keeps the year and time zone explicit and renders missing dates honestly', () => {
  expect(shortDate('2024-03-08T23:30:00.000Z')).toBe('2024/03/09')
  expect(fullDate(null)).toBe('未確認')
  expect(dateTime('2024-03-08T23:30:00.000Z')).toContain('08:30')
  expect(dateTime('2024-03-08T23:30:00.000Z')).toContain('日本時間')
})
