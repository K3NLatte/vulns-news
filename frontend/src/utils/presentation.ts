import { parsePublicHttpsUrl } from './publicUrl'
import type { Exploitation, Severity } from '../types/feed'

export const severityLabels: Record<Severity, string> = {
  critical: '緊急', high: '高', medium: '中', low: '低', none: 'なし', unknown: '未評価',
}
export const exploitationLabels: Record<Exploitation, string> = {
  observed: '悪用の報告あり', poc: 'PoC公開', 'not-observed': '悪用の報告なし', unknown: '悪用状況未確認',
}
export const relevanceLabels = {
  direct: '直接依存', transitive: '間接依存', review: '要確認',
} as const
export const confidenceLabels = { high: '高', medium: '中', low: '低', unknown: '未評価' } as const
const dateFormat = new Intl.DateTimeFormat('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', timeZone: 'Asia/Tokyo' })
const fullDateFormat = new Intl.DateTimeFormat('ja-JP', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'Asia/Tokyo' })
export function shortDate(value: string | null) { return value ? dateFormat.format(new Date(value)) : '未確認' }
export function fullDate(value: string | null) { return value ? `${fullDateFormat.format(new Date(value))}（日本時間）` : '未確認' }

// Future API responses are untrusted too. Do not render non-HTTPS reference links.
export function safeExternalUrl(value: unknown): string | undefined {
  return parsePublicHttpsUrl(value)?.href
}

const dateTimeFormat = new Intl.DateTimeFormat('ja-JP', {
  year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
  timeZone: 'Asia/Tokyo', hour12: false,
})
export function dateTime(value: string | null) {
  return value ? `${dateTimeFormat.format(new Date(value))}（日本時間）` : '未確認'
}
