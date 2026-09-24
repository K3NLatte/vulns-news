export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type Exploitation = 'observed' | 'poc' | 'not-observed'
export type FeedSort = 'newest' | 'severity'
export type FeedScope = 'all' | 'repository'

export interface FeedQuery {
  scope: FeedScope
  repositoryUrl?: string
  search: string
  severity: Severity | 'all'
  sort: FeedSort
}

export interface FeedItem {
  id: string
  advisoryId: string
  title: string
  product: string
  affectedVersions: string
  fixedVersion: string
  severity: Severity
  cvss: number | null
  publishedAt: string
  updatedAt: string
  summary: string
  exploitation: Exploitation
  affectedComponent: string
  remediation: string[]
  analysis: {
    summary: string
    evidence: string
    confidence: 'high' | 'medium' | 'low'
  }
  relevance?: {
    kind: 'direct' | 'transitive' | 'review'
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
}

export interface FeedOptions {
  signal?: AbortSignal
  scenario?: 'ready' | 'empty' | 'error'
  delayMs?: number
}

export type RepositoryUrlResult =
  | { ok: true; url: string; label: string }
  | { ok: false; message: string }
