export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'
export type Exploitation = 'observed' | 'poc' | 'not-observed' | 'unknown'
export type FeedSort = 'newest' | 'severity' | 'relevance'
export type FeedScope = 'all' | 'repository'
export type ReviewPriority = 'urgent' | 'high' | 'medium' | 'low' | 'review'

export interface FeedQuery {
  scope: FeedScope
  repositoryUrl?: string
  search: string
  cursor?: string
  severity: Severity | 'all'
  sort: FeedSort
}

export interface FeedItem {
  id: string
  advisoryId: string
  title: string
  product: string | null
  affectedVersions: string | null
  fixedVersion: string | null
  severity: Severity
  cvss: number | null
  assessment?: 'unverified'
  publishedAt: string | null
  updatedAt: string | null
  submittedAt?: string
  summary: string
  exploitation: Exploitation
  affectedComponent: string | null
  remediation: string[]
  proofOfConcept?: {
    language: string
    code: string
    conditions: string[]
  }
  /** Repository-specific outcome in the design mock; not a backend API contract. */
  repositoryAnalysis?: 'analyzed' | 'pending'
  analysis: {
    summary: string | null
    evidence: string | null
    confidence: 'high' | 'medium' | 'low' | 'unknown'
  }
  relevance?: {
    kind: 'direct' | 'transitive' | 'review'
    priority: ReviewPriority
    /** 暫定モックの関連度（0〜100）。重要度や依存種別とは別の値。未評価なら省略。 */
    score?: number
    reason: string
    packageName: string
    installedVersion: string
  }
  sources: {
    name: string
    url: string
    kind: 'vendor' | 'reference'
  }[]
}

export interface FeedResult {
  items: FeedItem[]
  /** Selected scope before search and severity filters. */
  total: number
  /** Number of items after all filters. */
  matchedTotal: number
  generatedAt: string
  /** Opaque cursor supplied by the adapter; totals may exceed this page. */
  nextCursor?: string | null
  /** Invalid rows omitted at the data boundary. */
  rejectedCount?: number
}

export interface FeedOptions {
  signal?: AbortSignal
  scenario?: 'ready' | 'empty' | 'error'
  delayMs?: number
}

export type RepositoryUrlResult =
  | { ok: true; url: string; label: string }
  | { ok: false; message: string }
