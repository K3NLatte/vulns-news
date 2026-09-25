import { describe, expect, it } from 'vitest'
import { isWellFormedText, MAX_URL_LENGTH, parsePublicHttpsUrl } from './publicUrl'
import { safeExternalUrl } from './presentation'
import { normalizeReportInput } from '../services/reports'

describe('public advisory URL boundary', () => {
  it.each([
    [' HTTPS://EXAMPLE.ORG:443/report?q=1#details ', 'https://example.org/report?q=1#details'],
    ['https://example.org./a%20b', 'https://example.org/a%20b'],
    ['https://例え.jp/記事', 'https://xn--r8jz45g.jp/%E8%A8%98%E4%BA%8B'],
    ['https://example.org?contact=a@example.org', 'https://example.org/?contact=a@example.org'],
  ])('keeps legitimate URL semantics: %s', (input, expected) => {
    expect(parsePublicHttpsUrl(input)?.href).toBe(expected)
    expect(safeExternalUrl(input)).toBe(expected)
    expect(normalizeReportInput(input)).toMatchObject({ ok: true, key: expected.split('#')[0], kind: 'url' })
  })

  it.each([
    null, undefined, {}, [], 42,
    '//example.org/report', 'https:example.org/report',
    'https://@example.org/report', 'https://user@example.org/report',
    'https://example.org:8443/report', 'https://example.org/a b',
    'https://example.org/a\\b', 'https://example.org/%0aheader',
    'https://localhost/report', 'https://service.internal/report',
    'https://0x7f000001/report', 'https://[2001:db8::1]/report',
    'https://-invalid.example.org/report', 'https://a..example.org/report',
    'https://example.org/' + 'a'.repeat(MAX_URL_LENGTH),
    'https://example.org/' + String.fromCharCode(0xd800),
    String.fromCharCode(0) + 'https://example.org/report',
  ])('rejects unsupported values consistently: %s', input => {
    expect(parsePublicHttpsUrl(input)).toBeUndefined()
    expect(safeExternalUrl(input)).toBeUndefined()
    expect(normalizeReportInput(input).ok).toBe(false)
  })

  it('accepts paired Unicode and rejects lone UTF-16 surrogates', () => {
    expect(isWellFormedText('日本語 👩‍💻')).toBe(true)
    expect(isWellFormedText(String.fromCharCode(0xd800))).toBe(false)
    expect(isWellFormedText(String.fromCharCode(0xdc00))).toBe(false)
    expect(isWellFormedText(String.fromCharCode(0xd800) + 'x')).toBe(false)
  })
})
