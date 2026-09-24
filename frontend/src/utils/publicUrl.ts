export const MAX_URL_LENGTH = 2048

export function isWellFormedText(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++index)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false
    } else if (code >= 0xdc00 && code <= 0xdfff) return false
  }
  return true
}

/** URL syntax for public advisory links. DNS/redirect and SSRF checks belong to the server. */
export function parsePublicHttpsUrl(input: unknown): URL | undefined {
  if (typeof input !== 'string' || input.length > MAX_URL_LENGTH || !isWellFormedText(input)) return undefined
  if (/[\u0000-\u001f\u007f\\]/u.test(input)) return undefined
  const value = input.trim()
  if (!/^https:\/\//iu.test(value) || /\s/u.test(value) || /%(?:0[0-9a-f]|1[0-9a-f]|7f)/iu.test(value)) return undefined
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' || url.username || url.password || url.port || /^https:\/\/[^/?#]*@/iu.test(value)) return undefined
    const host = url.hostname.replace(/\.$/u, '')
    if (host.length > 253 || !host.includes('.') || /^[\d.]+$/u.test(host) || host.includes(':')) return undefined
    if (/(?:^|\.)(?:localhost|local|internal|lan|home|test|invalid)$/iu.test(host)) return undefined
    if (!host.split('.').every(label => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/iu.test(label))) return undefined
    url.hostname = host
    return url
  } catch { return undefined }
}
