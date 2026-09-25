import { onScopeDispose, getCurrentScope, shallowRef, ref } from 'vue'
import { createWorkspaceStore, WorkspaceActionError, type WorkspaceStorage } from '../services/workspace'
import type { SavedReportReference } from '../types/reports'
import type { ReviewStatus } from '../types/workspace'

type Store = ReturnType<typeof createWorkspaceStore>
export type WorkspaceResult<T = void> = { ok: true; value: T } | {
  ok: false; message: string; kind: 'validation' | 'storage' | 'conflict' | 'busy'
}
// A real adapter can await a server response before exposing a new snapshot.
// The local adapter commits only after persistence succeeds; failure rolls back.
export type WorkspaceAdapter = { [K in keyof Store]: Store[K] extends (...args: infer A) => infer R
  ? K extends 'snapshot' | 'getReviewStatus' | 'exportRecovery' | 'notifyStorageChange'
    ? (...args: A) => R : (...args: A) => R | Promise<R> : never }

export function useWorkspace(storage?: WorkspaceStorage, adapter?: WorkspaceAdapter) {
  const store = adapter ?? createWorkspaceStore(storage)
  const initial = store.snapshot()
  const user = shallowRef(initial.user)
  const repositories = shallowRef(initial.repositories)
  const activeRepositoryId = ref(initial.activeRepositoryId)
  const savedIds = shallowRef(initial.savedIds)
  const savedReportReferences = shallowRef(initial.savedReportReferences)
  const comments = shallowRef(initial.comments)
  const reviewStatuses = shallowRef(initial.reviewStatuses)
  const storageError = ref(initial.storageError)
  const storageNotice = ref(initial.storageNotice)
  const conflict = ref(initial.conflict)
  const recoveryAvailable = ref(initial.recoveryAvailable)
  const pending = ref(false)
  const pendingAction = ref('')

  function sync() {
    const next = store.snapshot()
    user.value = next.user
    repositories.value = next.repositories
    activeRepositoryId.value = next.activeRepositoryId
    savedIds.value = next.savedIds
    savedReportReferences.value = next.savedReportReferences
    comments.value = next.comments
    reviewStatuses.value = next.reviewStatuses
    storageError.value = next.storageError
    storageNotice.value = next.storageNotice
    conflict.value = next.conflict
    recoveryAvailable.value = next.recoveryAvailable
  }
  async function change<T>(name: string, action: () => T | Promise<T>): Promise<WorkspaceResult<T>> {
    if (pending.value) return { ok: false, message: '処理中です。完了後にもう一度お試しください。', kind: 'busy' }
    pending.value = true
    pendingAction.value = name
    try { return { ok: true, value: await action() } }
    catch (error) {
      const snapshot = store.snapshot()
      const message = error instanceof WorkspaceActionError ? error.message : '処理を完了できませんでした。もう一度お試しください。'
      return { ok: false, message, kind: snapshot.conflict ? 'conflict' : snapshot.storageError ? 'storage' : 'validation' }
    } finally { pending.value = false; pendingAction.value = ''; sync() }
  }

  const onStorage = (event: StorageEvent) => {
    store.notifyStorageChange(event.key)
    sync()
  }
  if (typeof window !== 'undefined' && getCurrentScope()) {
    window.addEventListener('storage', onStorage)
    onScopeDispose(() => window.removeEventListener('storage', onStorage))
  }

  return {
    user, repositories, activeRepositoryId, savedIds, savedReportReferences, comments, reviewStatuses,
    storageError, storageNotice, conflict, recoveryAvailable, pending, pendingAction,
    login: (displayName: string) => change('login', () => store.login(displayName)),
    logout: () => change('logout', () => store.logout()),
    addRepository: (url: string) => change('addRepository', async () => {
      const result = await store.addRepository(url)
      if (!result.ok) throw new WorkspaceActionError(result.message)
      return result.repository
    }),
    removeRepository: (id: string) => change('removeRepository', () => store.removeRepository(id)),
    selectRepository: (id: string) => change('selectRepository', () => store.selectRepository(id)),
    toggleSaved: (articleId: string, reference?: SavedReportReference) => change('toggleSaved', () => store.toggleSaved(articleId, reference)),
    addComment: (articleId: string, body: string, reference?: SavedReportReference) => change('addComment', () => store.addComment(articleId, body, reference)),
    deleteComment: (id: string) => change('deleteComment', () => store.deleteComment(id)),
    setReviewStatus: (repositoryId: string, articleId: string, status: ReviewStatus, reference?: SavedReportReference) => change('setReviewStatus', () => store.setReviewStatus(repositoryId, articleId, status, reference)),
    getReviewStatus: (repositoryId: string, articleId: string) => reviewStatuses.value[JSON.stringify([repositoryId, articleId])] ?? 'unreviewed',
    reloadLatest: () => change('reloadLatest', () => store.reloadLatest()),
    resetRecovery: () => change('resetRecovery', () => store.resetRecovery()),
    exportRecovery: () => store.exportRecovery(),
  }
}
