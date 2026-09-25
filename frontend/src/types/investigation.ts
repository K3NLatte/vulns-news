export type InvestigationStatus = 'queued' | 'collecting' | 'analyzing' | 'completed' | 'failed' | 'cancelled'
export interface InvestigationJob {
  id: string
  key: string
  label: string
  kind: 'submission' | 'reanalysis' | 'repository'
  status: InvestigationStatus
  createdAt: string
  startedAt?: string
  reportIds: string[]
  reusedCount: number
  newCount: number
  error?: string
}