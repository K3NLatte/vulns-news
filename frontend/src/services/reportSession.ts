import type { InvestigationJob } from '../types/investigation'
import type { ReportLifecycle, ReportRevision } from '../types/reports'

export const MAX_REPORT_JOBS = 100
export const MAX_ACTIVE_REPORT_JOBS = 5
export const MAX_REPORT_SESSION_LENGTH = 200_000

type StoredJob = Pick<InvestigationJob, 'kind' | 'key' | 'createdAt' | 'startedAt' | 'status'>

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Stored dates are compared lexically and used in date arithmetic. */
export function isStoredDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) return false
  const time = Date.parse(value)
  return Number.isFinite(time) && new Date(time).toISOString() === value
}

export function parseStoredJobs(value: unknown, _now: string): StoredJob[] {
  if (!Array.isArray(value)) return []
  return value.slice(0, MAX_REPORT_JOBS).flatMap((row): StoredJob[] => {
    if (!isRecord(row) || typeof row.key !== 'string' || row.key.length > 2048 || !isStoredDate(row.createdAt)) return []
    if (row.kind !== 'submission' && row.kind !== 'repository' && row.kind !== 'reanalysis') return []
    if (row.status !== 'queued' && row.status !== 'collecting' && row.status !== 'analyzing' && row.status !== 'completed' && row.status !== 'failed' && row.status !== 'cancelled') return []
    return [{ kind: row.kind, key: row.key, createdAt: row.createdAt, status: row.status, ...(isStoredDate(row.startedAt) ? { startedAt: row.startedAt } : {}) }]
  })
}

export function parseStoredLifecycle(value: unknown, baseline: ReportLifecycle, _now: string): ReportLifecycle | null {
  if (!isRecord(value) || value.articleId !== baseline.articleId || value.origin !== baseline.origin) return null
  if (!isStoredDate(value.trackingUntil) || !(value.lastAnalyzedAt === null || isStoredDate(value.lastAnalyzedAt)) || !(value.nextCheckAt === null || isStoredDate(value.nextCheckAt))) return null
  if (typeof value.revision !== 'number' || !Number.isSafeInteger(value.revision) || value.revision < baseline.revision) return null
  if (!Array.isArray(value.history) || value.history.length > MAX_REPORT_JOBS) return null
  // A stored lifecycle cannot turn an unfinished request into an analyzed report.
  if (baseline.revision === 0 && value.revision !== 0) return null
  const history: ReportRevision[] = []
  for (const entry of value.history) {
    if (!isRecord(entry) || typeof entry.revision !== 'number' || !Number.isSafeInteger(entry.revision) || entry.revision < 1 || !isStoredDate(entry.analyzedAt)) return null
    if (entry.reason !== 'initial' && entry.reason !== 'scheduled' && entry.reason !== 'manual') return null
    const previous = history.at(-1)
    if (previous && (entry.revision !== previous.revision + 1 || entry.analyzedAt < previous.analyzedAt || entry.reason === 'initial')) return null
    history.push({ revision: entry.revision, analyzedAt: entry.analyzedAt, reason: entry.reason })
  }
  const last = history.at(-1)
  if (value.revision === 0 ? history.length !== 0 || value.lastAnalyzedAt !== null : !last || last.revision !== value.revision || last.analyzedAt !== value.lastAnalyzedAt) return null
  if (value.nextCheckAt !== null && (value.nextCheckAt >= value.trackingUntil || (value.lastAnalyzedAt !== null && value.nextCheckAt <= value.lastAnalyzedAt))) return null
  return { articleId: baseline.articleId, origin: baseline.origin, revision: value.revision, lastAnalyzedAt: value.lastAnalyzedAt, trackingUntil: value.trackingUntil, nextCheckAt: value.nextCheckAt, history }
}
