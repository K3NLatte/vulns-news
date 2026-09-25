import type { InvestigationJob } from './investigation'

export type ReportInputKind = 'cve' | 'ghsa' | 'url'

export type ReportInputResult =
  | { ok: true; key: string; kind: ReportInputKind }
  | { ok: false; message: string }

export type ReportOrigin = 'feed' | 'submitted' | 'repository'
export type ReportUpdateReason = 'initial' | 'scheduled' | 'manual'

export interface ReportRevision {
  revision: number
  analyzedAt: string
  reason: ReportUpdateReason
}

/** Local interaction model; this is not an agreed backend API contract. */
export interface ReportLifecycle {
  articleId: string
  lastAnalyzedAt: string | null
  trackingUntil: string
  nextCheckAt: string | null
  revision: number
  history: ReportRevision[]
  origin: ReportOrigin
}

/** Minimal local bookmark; report facts are reconstructed, never trusted from storage. */
export interface SavedReportReference {
  input: string
  createdAt: string
}

export type ReportActionResult =
  | { ok: true; job: InvestigationJob; status: 'accepted' | 'duplicate' | 'reused' }
  | { ok: false; reason: 'invalid' | 'capacity' | 'history' | 'network' | 'conflict' | 'aborted' | 'busy'; message: string }

/** Request admission is asynchronous; the local job then owns the longer analysis lifecycle. */
export interface ReportCommand {
  kind: 'submit' | 'reanalyze' | 'scanRepository' | 'retry' | 'cancel' | 'renew' | 'dismissJob'
  key: string
}
export type ReportCommandAdapter = (
  command: ReportCommand,
  options: { signal: AbortSignal },
) => Promise<{ ok: true } | { ok: false; reason: 'network' | 'conflict' | 'capacity' }>
