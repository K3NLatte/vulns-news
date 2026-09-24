export interface WorkspaceUser {
  id: string
  displayName: string
}

export interface WorkspaceRepository {
  id: string
  url: string
  label: string
}

export interface FeedComment {
  id: string
  articleId: string
  authorId: string
  authorName: string
  body: string
  createdAt: string
}

export type ReviewStatus = 'unreviewed' | 'investigating' | 'resolved' | 'not-affected'

export interface WorkspaceData {
  repositories: WorkspaceRepository[]
  activeRepositoryId: string | null
  savedIds: string[]
  comments: FeedComment[]
  reviewStatuses: Record<string, ReviewStatus>
}

export interface WorkspaceSnapshot extends WorkspaceData {
  user: WorkspaceUser | null
  storageError: string
}

export type AddRepositoryResult =
  | { ok: true; repository: WorkspaceRepository }
  | { ok: false; message: string }
