import { describe, expect, it } from 'vitest'
import { safeExternalUrl } from './presentation'

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
