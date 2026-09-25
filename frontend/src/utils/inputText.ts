// Preserve line breaks and tabs in prose, but reject misleading invisible controls.
const unsafeCharacters = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\uD800-\uDFFF]|\u034f/u
export const hasUnsafeCharacters = (value: string): boolean => unsafeCharacters.test(value)
export const codePointLength = (value: string): number => Array.from(value).length
export function isIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) return false
  const timestamp = Date.parse(value)
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value
}
