import { ref } from 'vue'
import { createWorkspaceStore, type WorkspaceStorage } from '../services/workspace'
import type { ReviewStatus } from '../types/workspace'

export function useWorkspace(storage?: WorkspaceStorage) {
  const store = createWorkspaceStore(storage)
  const initial = store.snapshot()
  const user = ref(initial.user)
  const repositories = ref(initial.repositories)
  const activeRepositoryId = ref(initial.activeRepositoryId)
  const savedIds = ref(initial.savedIds)
  const comments = ref(initial.comments)
  const reviewStatuses = ref(initial.reviewStatuses)
  const storageError = ref(initial.storageError)

  function sync() {
    const next = store.snapshot()
    user.value = next.user
    repositories.value = next.repositories
    activeRepositoryId.value = next.activeRepositoryId
    savedIds.value = next.savedIds
    comments.value = next.comments
    reviewStatuses.value = next.reviewStatuses
    storageError.value = next.storageError
  }
  function change<T>(action: () => T): T {
    try { return action() } finally { sync() }
  }

  return {
    user, repositories, activeRepositoryId, savedIds, comments, reviewStatuses, storageError,
    login: (displayName: string) => change(() => store.login(displayName)),
    logout: () => change(() => store.logout()),
    addRepository: (url: string) => change(() => store.addRepository(url)),
    removeRepository: (id: string) => change(() => store.removeRepository(id)),
    selectRepository: (id: string) => change(() => store.selectRepository(id)),
    toggleSaved: (articleId: string) => change(() => store.toggleSaved(articleId)),
    addComment: (articleId: string, body: string) => change(() => store.addComment(articleId, body)),
    deleteComment: (id: string) => change(() => store.deleteComment(id)),
    setReviewStatus: (repositoryId: string, articleId: string, status: ReviewStatus) => change(() => store.setReviewStatus(repositoryId, articleId, status)),
    getReviewStatus: (repositoryId: string, articleId: string) => {
      // Read the ref as well, so template/computed consumers react to explicit changes.
      return reviewStatuses.value[JSON.stringify([repositoryId, articleId])] ?? 'unreviewed'
    },
  }
}
