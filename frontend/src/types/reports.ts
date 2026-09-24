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
