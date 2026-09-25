import { parseRepositoryUrl } from './feed'
import { localId } from '../utils/localId'
import { hasUnsafeCharacters, codePointLength, isIsoTimestamp } from '../utils/inputText'
import { restoreSavedReport } from './reports'
import type { SavedReportReference } from '../types/reports'
import type {
  AddRepositoryResult, FeedComment, ReviewStatus, WorkspaceData,
  WorkspaceSnapshot, WorkspaceUser,
} from '../types/workspace'

export interface WorkspaceStorage {
  session: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null
  local: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null
}

type StoredValue = { kind: 'missing' } | { kind: 'failed' } | { kind: 'value'; value: unknown; raw: string }
const maxStoredLength = 2_000_000
const guestKey = 'vulns-news:workspace:guest:v1'
const activeKey = 'vulns-news:workspace:active:v1'
const profileKey = (name: string) => `vulns-news:workspace:profile:v1:${encodeURIComponent(name)}`
const statuses: ReviewStatus[] = ['unreviewed', 'investigating', 'resolved', 'not-affected']
const emptyData = (): WorkspaceData => ({ repositories: [], activeRepositoryId: null, savedIds: [], savedReportReferences: {}, comments: [], reviewStatuses: {} })
const copy = <T>(value: T): T => structuredClone(value)
const legacyNormalizedName = (name: string) => name.normalize('NFKC').toLocaleLowerCase('ja-JP')
function normalizedName(name: string): string {
  let normalized = legacyNormalizedName(name)
  while (normalized !== name) {
    name = normalized
    normalized = legacyNormalizedName(name)
  }
  return normalized
}
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
const isText = (value: unknown, limit: number): value is string => typeof value === 'string'
  && value.trim().length > 0 && codePointLength(value) <= limit && !hasUnsafeCharacters(value)
const isId = (value: unknown): value is string => isText(value, 200) && !/\s/u.test(value)
const reviewKey = (repositoryId: string, articleId: string) => JSON.stringify([repositoryId, articleId])

function inputText(value: string, limit: number, label: string): string {
  const text = value.trim()
  if (hasUnsafeCharacters(value)) throw new WorkspaceActionError(`${label}に制御文字や非表示の文字は使用できません。`)
  if (!isText(text, limit)) throw new WorkspaceActionError(`${label}は1〜${limit}文字で入力してください。`)
  return text
}

function articleIdInput(value: string): string {
  if (!isId(value)) throw new WorkspaceActionError('記事IDが不正です。')
  return value
}

function validateUser(value: unknown): value is WorkspaceUser {
  return isRecord(value) && isId(value.id) && value.id !== 'guest'
    && isText(value.displayName, 40) && value.displayName.trim() === value.displayName && !/\s{2,}|[\r\n\t]/u.test(value.displayName)
}

function validateData(value: unknown, authorId: string): value is WorkspaceData {
  if (!isRecord(value) || !Array.isArray(value.repositories) || value.repositories.length > 20
    || !Array.isArray(value.savedIds) || value.savedIds.length > 5000
    || !Array.isArray(value.comments) || value.comments.length > 500
    || !isRecord(value.reviewStatuses) || Object.keys(value.reviewStatuses).length > 5000) return false

  const repositories = value.repositories
  for (const repository of repositories) {
    if (!isRecord(repository) || !isId(repository.id) || typeof repository.url !== 'string') return false
    const parsed = parseRepositoryUrl(repository.url)
    if (!parsed.ok || parsed.url !== repository.url.toLowerCase() || typeof repository.label !== 'string'
      || parsed.label.toLowerCase() !== repository.label.toLowerCase()) return false
  }
  if (new Set(repositories.map(repository => repository.id)).size !== repositories.length
    || new Set(repositories.map(repository => repository.url.toLowerCase())).size !== repositories.length) return false
  if (value.activeRepositoryId !== null && !repositories.some(repository => repository.id === value.activeRepositoryId)) return false
  if (!value.savedIds.every(isId) || new Set(value.savedIds).size !== value.savedIds.length) return false
  const referencedIds = new Set<unknown>(value.savedIds)
  for (const item of value.comments) if (isRecord(item)) referencedIds.add(item.articleId)
  for (const key of Object.keys(value.reviewStatuses)) {
    try { const parts: unknown = JSON.parse(key); if (Array.isArray(parts)) referencedIds.add(parts[1]) } catch { /* invalid status is rejected below */ }
  }
  // Version 1 saves made before submission bookmarks have no reference field.
  if (value.savedReportReferences !== undefined) {
    if (!isRecord(value.savedReportReferences) || Object.keys(value.savedReportReferences).length > 10_000) return false
    for (const [id, reference] of Object.entries(value.savedReportReferences)) {
      if (!isId(id) || !referencedIds.has(id) || !restoreSavedReport(id, reference)) return false
    }
  }
  for (const comment of value.comments) {
    if (!isRecord(comment) || !isId(comment.id) || !isId(comment.articleId) || comment.authorId !== authorId
      || !isText(comment.authorName, 40) || !isText(comment.body, 2000)
      || !isIsoTimestamp(comment.createdAt)
      || (comment.articleId.startsWith('submitted-') && (!isRecord(value.savedReportReferences) || !restoreSavedReport(comment.articleId, value.savedReportReferences[comment.articleId])))) return false
  }
  if (new Set(value.comments.map(comment => comment.id)).size !== value.comments.length) return false
  for (const [key, status] of Object.entries(value.reviewStatuses)) {
    if (!statuses.includes(status as ReviewStatus)) return false
    let parts: unknown
    try { parts = JSON.parse(key) } catch { return false }
    if (!Array.isArray(parts) || parts.length !== 2 || !isId(parts[0]) || !isId(parts[1])
      || reviewKey(parts[0], parts[1]) !== key || !repositories.some(repository => repository.id === parts[0])
      || (parts[1].startsWith('submitted-') && (!isRecord(value.savedReportReferences) || !restoreSavedReport(parts[1], value.savedReportReferences[parts[1]])))) return false
  }
  return true
}

function restoreData(value: WorkspaceData): WorkspaceData {
  // Restore only known fields; do not promote unknown fields into the writable model.
  return {
    repositories: value.repositories.map(item => ({ id: item.id, url: item.url.toLowerCase(), label: item.label })),
    activeRepositoryId: value.activeRepositoryId,
    savedIds: [...value.savedIds],
    savedReportReferences: Object.fromEntries(Object.entries(value.savedReportReferences ?? {}).map(([id, reference]) => [id, {
      input: reference.input, createdAt: reference.createdAt,
    }])),
    comments: value.comments.map(item => ({ id: item.id, articleId: item.articleId, authorId: item.authorId,
      authorName: item.authorName, body: item.body, createdAt: item.createdAt })),
    reviewStatuses: { ...value.reviewStatuses },
  }
}

function salvageData(value: unknown, authorId: string): { data: WorkspaceData; recovered: boolean } {
  if (validateData(value, authorId)) return { data: restoreData(value), recovered: false }
  const restored = emptyData()
  if (!isRecord(value)) return { data: restored, recovered: true }
  // Isolate invalid rows while keeping valid rows readable. The original is not
  // overwritten until the user chooses recovery and its backup is saved.
  for (const candidate of Array.isArray(value.repositories) ? value.repositories.slice(0, 20) : []) {
    const next = { ...restored, repositories: [...restored.repositories, candidate] }
    if (validateData(next, authorId)) restored.repositories = next.repositories
  }
  if (restored.repositories.some(item => item.id === value.activeRepositoryId)) restored.activeRepositoryId = value.activeRepositoryId as string
  for (const candidate of Array.isArray(value.savedIds) ? value.savedIds.slice(0, 5000) : []) {
    if (isId(candidate) && !restored.savedIds.includes(candidate)) restored.savedIds.push(candidate)
  }
  const referencesFor = (articleId: unknown) => {
    const reference = isId(articleId) && isRecord(value.savedReportReferences) ? value.savedReportReferences[articleId] : undefined
    return isId(articleId) && restoreSavedReport(articleId, reference)
      ? { ...restored.savedReportReferences, [articleId]: reference as SavedReportReference } : restored.savedReportReferences
  }
  for (const candidate of Array.isArray(value.comments) ? value.comments.slice(0, 500) : []) {
    const next = { ...restored, comments: [...restored.comments, candidate], savedReportReferences: referencesFor(isRecord(candidate) ? candidate.articleId : undefined) }
    if (validateData(next, authorId)) { restored.comments = next.comments; restored.savedReportReferences = next.savedReportReferences }
  }
  for (const [key, status] of isRecord(value.reviewStatuses) ? Object.entries(value.reviewStatuses).slice(0, 5000) : []) {
    let articleId: unknown
    try { const parts: unknown = JSON.parse(key); if (Array.isArray(parts)) articleId = parts[1] } catch { continue }
    const next = { ...restored, reviewStatuses: { ...restored.reviewStatuses, [key]: status }, savedReportReferences: referencesFor(articleId) }
    if (validateData(next, authorId)) { restored.reviewStatuses = next.reviewStatuses as WorkspaceData['reviewStatuses']; restored.savedReportReferences = next.savedReportReferences }
  }
  for (const [id, reference] of isRecord(value.savedReportReferences) ? Object.entries(value.savedReportReferences).slice(0, 10_000) : []) {
    const referenced = restored.savedIds.includes(id) || restored.comments.some(item => item.articleId === id)
      || Object.keys(restored.reviewStatuses).some(key => (JSON.parse(key) as string[])[1] === id)
    if (referenced && isId(id) && restoreSavedReport(id, reference)) restored.savedReportReferences[id] = reference as SavedReportReference
  }
  return { data: restoreData(restored), recovered: true }
}

function browserStorage(name: 'sessionStorage' | 'localStorage'): Storage | null {
  try { return typeof window === 'undefined' ? null : window[name] } catch { return null }
}

export class WorkspaceActionError extends Error {}

type RecoveryRecord = { target: WorkspaceStorage['session']; key: string; raw: string; replacement?: unknown }

/** Browser-local profile adapter. No authentication, passwords, tokens, or network requests. */
export function createWorkspaceStore(storage: WorkspaceStorage = {
  session: browserStorage('sessionStorage'), local: browserStorage('localStorage'),
}) {
  let storageError = ''
  let storageNotice = ''
  let conflict = false
  const recovery = new Map<string, RecoveryRecord>()
  const unreadable = new Set<string>()
  const recoveryMessage = '保存データの一部が不正な形式のため読み込めません。元データは保持しています。エクスポートして確認後、保存を再開できます。'
  const block = (target: WorkspaceStorage['session'], key: string, raw: string, replacement?: unknown) => {
    recovery.set(key, { target, key, raw, replacement })
    storageError = recoveryMessage
  }
  const read = (target: WorkspaceStorage['session'], key: string): StoredValue => {
    let raw: string | null = null
    try {
      if (!target) return { kind: 'missing' }
      raw = target.getItem(key)
      unreadable.delete(key)
      recovery.delete(key)
      if (raw === null) return { kind: 'missing' }
      if (raw.length > maxStoredLength) throw new WorkspaceActionError('Stored data too large')
      return { kind: 'value', value: JSON.parse(raw), raw }
    } catch {
      if (raw !== null) block(target, key, raw)
      else { unreadable.add(key); storageError = '保存データを読み込めません。保存領域を確認して再試行してください。' }
      return { kind: 'failed' }
    }
  }
  const write = (target: WorkspaceStorage['session'], key: string, value: unknown): boolean => {
    try {
      if (!target) {
        storageNotice = '保存領域を利用できないため、この画面を閉じるまでの変更として保持します。'
        return true
      }
      const serialized = JSON.stringify(value)
      if (serialized.length > maxStoredLength) {
        storageError = '保存容量の上限（200万文字）を超えました。不要なコメントや保存記事を削除して再試行してください。'
        return false
      }
      target.setItem(key, serialized)
      return true
    } catch {
      storageError = 'このブラウザーに保存できません。変更は反映していません。保存領域を確認して再試行してください。'
      return false
    }
  }
  const remove = (target: WorkspaceStorage['session'], key: string): boolean => {
    try { target?.removeItem(key); return true } catch {
      storageError = 'ログイン状態を保存できません。保存領域を確認して再試行してください。'
      return false
    }
  }
  const viewKey = (name: string | null) => `vulns-news:workspace:view:v1:${encodeURIComponent(name ?? 'guest')}`
  const applyView = (value: WorkspaceData, name: string | null) => {
    const result = read(storage.session, viewKey(name))
    if (result.kind === 'value' && typeof result.value === 'string' && value.repositories.some(item => item.id === result.value)) {
      value.activeRepositoryId = result.value
    }
  }
  let guest = emptyData()
  const storedGuest = read(storage.session, guestKey)
  if (storedGuest.kind === 'value') {
    const stored = storedGuest.value
    if (isRecord(stored) && stored.version === 1) {
      const restored = salvageData(stored.data, 'guest')
      guest = restored.data
      if (restored.recovered) block(storage.session, guestKey, storedGuest.raw, { version: 1, data: guest })
    } else block(storage.session, guestKey, storedGuest.raw)
  }
  applyView(guest, null)
  const profileVersions = new Map<string, string | null>()
  const profiles = new Map<string, { user: WorkspaceUser; data: WorkspaceData }>()
  const readProfile = (name: string, legacyName = name) => {
    if (storage.local === null) return profiles.get(name) ?? null
    let result = read(storage.local, profileKey(name))
    let legacyProfile = false
    if (result.kind === 'missing' && legacyName !== name) {
      result = read(storage.local, profileKey(legacyName))
      legacyProfile = result.kind === 'value'
    }
    if (result.kind === 'missing') { profileVersions.set(name, null); return null }
    if (result.kind === 'failed') return undefined
    const stored = result.value
    if (!isRecord(stored) || stored.version !== 1 || !validateUser(stored.user) || normalizedName(stored.user.displayName) !== name) {
      block(storage.local, profileKey(name), result.raw)
      return undefined
    }
    const restored = salvageData(stored.data, stored.user.id)
    const profile = { user: { id: stored.user.id, displayName: stored.user.displayName }, data: restored.data }
    if (restored.recovered) block(storage.local, profileKey(name), result.raw, { version: 1, ...profile })
    if (legacyProfile && !write(storage.local, profileKey(name), stored)) return undefined
    profileVersions.set(name, legacyProfile ? JSON.stringify(stored) : result.raw)
    applyView(profile.data, name)
    profiles.set(name, profile)
    return profile
  }
  let user: WorkspaceUser | null = null
  let activeProfile: string | null = null
  let data = guest
  const activeResult = read(storage.session, activeKey)
  if (activeResult.kind === 'value') {
    const active = activeResult.value
    if (isRecord(active) && active.version === 1 && isText(active.name, maxStoredLength)) {
      const name = normalizedName(active.name)
      const profile = readProfile(name, active.name)
      if (profile) { user = profile.user; data = profile.data; activeProfile = name }
      else if (profile === null) remove(storage.session, activeKey)
    } else block(storage.session, activeKey, activeResult.raw)
  }

  const persist = (): boolean => {
    const key = activeProfile === null ? guestKey : profileKey(activeProfile)
    if (recovery.has(key)) { storageError = recoveryMessage; return false }
    if (unreadable.has(key)) { storageError = '保存内容を読み込めないため上書きしていません。「最新を読み込む」で再試行してください。'; return false }
    if (user && activeProfile !== null) {
      if (storage.local && profileVersions.has(activeProfile)) {
        try {
          if (storage.local.getItem(key) !== profileVersions.get(activeProfile)) {
            conflict = true
            storageError = '別のタブで保存内容が変更されています。変更は反映していません。「最新を読み込む」後に再試行してください。'
            return false
          }
        } catch { storageError = '保存済みの内容を確認できないため変更を反映していません。'; return false }
      }
      const value = { version: 1, user, data }
      if (!write(storage.local, key, value)) return false
      profileVersions.set(activeProfile, JSON.stringify(value))
      profiles.set(activeProfile, { user, data })
      return true
    }
    if (!write(storage.session, guestKey, { version: 1, data })) return false
    guest = data
    return true
  }
  const beginChange = () => { storageError = ''; conflict = false }
  const snapshot = (): WorkspaceSnapshot => copy({ ...data, user, storageError: storageError || (recovery.size ? recoveryMessage : ''), storageNotice, conflict, recoveryAvailable: recovery.size > 0 })
  const mutate = (change: () => void) => {
    beginChange()
    const previous = data
    data = copy(data)
    try {
      change()
      if (!persist()) throw new WorkspaceActionError(storageError)
    } catch (error) { data = previous; throw error }
  }
  const referenceInUse = (id: string) => data.savedIds.includes(id) || data.comments.some(item => item.articleId === id)
    || Object.keys(data.reviewStatuses).some(key => (JSON.parse(key) as string[])[1] === id)
  const cleanReferences = () => {
    for (const id of Object.keys(data.savedReportReferences)) if (!referenceInUse(id)) delete data.savedReportReferences[id]
  }
  const keepReference = (id: string, reference?: SavedReportReference) => {
    if (reference) {
      if (!restoreSavedReport(id, reference)) throw new WorkspaceActionError('記事の情報が不正です。')
      data.savedReportReferences[id] = { input: reference.input, createdAt: reference.createdAt }
    }
    if (id.startsWith('submitted-') && !data.savedReportReferences[id]) throw new WorkspaceActionError('記事の参照情報が見つかりません。記事を開き直してください。')
  }

  return {
    snapshot,
    login(displayName: string) {
      if (/[\r\n\t]/u.test(displayName)) throw new WorkspaceActionError('表示名には改行やタブを使用できません。')
      const name = inputText(displayName, 40, '表示名').replace(/\s+/gu, ' ')
      beginChange()
      const key = normalizedName(name)
      for (const recoveryKey of recovery.keys()) {
        if (recoveryKey.startsWith('vulns-news:workspace:profile:') && recoveryKey !== profileKey(key)) recovery.delete(recoveryKey)
      }
      let profile = readProfile(key, legacyNormalizedName(name))
      if (profile === undefined) throw new WorkspaceActionError('保存済みのアカウントを読み込めないため、ログインできません。元データをエクスポートして確認してください。')
      const isNew = profile === null
      if (!profile) {
        if (recovery.has(guestKey) || unreadable.has(guestKey)) throw new WorkspaceActionError('ゲストの保存データを確認してからログインしてください。元データは変更していません。')
        const newUser = { id: `user:${localId()}`, displayName: name }
        const transferred = copy(guest)
        transferred.comments = transferred.comments.map(comment => ({ ...comment, authorId: newUser.id, authorName: name }))
        profile = { user: newUser, data: transferred }
      }
      const previous = { user, data, activeProfile }
      if (!write(storage.session, activeKey, { version: 1, name: key })) throw new WorkspaceActionError('ログイン状態を保存できませんでした。保存領域を確認して再試行してください。')
      user = profile.user; data = profile.data; activeProfile = key
      if (isNew && !persist()) {
        const failure = storageError
        user = previous.user; data = previous.data; activeProfile = previous.activeProfile
        if (activeProfile) write(storage.session, activeKey, { version: 1, name: activeProfile })
        else remove(storage.session, activeKey)
        storageError = failure
        throw new WorkspaceActionError('アカウントを保存できませんでした。保存領域を確認して再試行してください。')
      }
      // Clear transferred guest content only after both records are durable.
      if (isNew && storage.local !== null && storage.session !== null) {
        if (write(storage.session, guestKey, { version: 1, data: emptyData() })) guest = emptyData()
        else {
          const failure = storageError
          // Restore both visible identity and the session if guest transfer fails.
          // If cleanup is also blocked, keep that original profile recoverable.
          if (!remove(storage.local, profileKey(key))) storageNotice = '作成途中のプロフィールが保存領域に残っています。次回ログインで確認できます。'
          profiles.delete(key); profileVersions.delete(key)
          user = previous.user; data = previous.data; activeProfile = previous.activeProfile
          if (activeProfile) write(storage.session, activeKey, { version: 1, name: activeProfile })
          else remove(storage.session, activeKey)
          storageError = failure
          throw new WorkspaceActionError('ゲストの作業を移行できなかったため、ログインを取り消しました。保存領域を確認して再試行してください。')
        }
      } else if (!isNew && (guest.savedIds.length || guest.repositories.length || guest.comments.length)) {
        storageNotice = 'ゲストの作業はこのタブに保持しています。ログアウトすると戻れます。'
      }
    },
    logout() {
      beginChange()
      if (!remove(storage.session, activeKey)) throw new WorkspaceActionError(storageError)
      user = null; activeProfile = null; data = guest
      for (const key of recovery.keys()) if (key.startsWith('vulns-news:workspace:profile:')) recovery.delete(key)
      storageNotice = ''
    },
    addRepository(url: string): AddRepositoryResult {
      const parsed = parseRepositoryUrl(url)
      if (!parsed.ok) return parsed
      if (data.repositories.some(repository => repository.url.toLowerCase() === parsed.url.toLowerCase())) return { ok: false, message: 'このリポジトリは登録済みです。' }
      if (data.repositories.length >= 20) return { ok: false, message: 'リポジトリは20件まで登録できます。' }
      const repository = { id: `repo:${localId()}`, url: parsed.url, label: parsed.label }
      try { mutate(() => { data.repositories.push(repository); data.activeRepositoryId = repository.id }) }
      catch { return { ok: false, message: storageError || 'リポジトリを保存できませんでした。' } }
      return { ok: true, repository: copy(repository) }
    },
    removeRepository(id: string) {
      if (!data.repositories.some(repository => repository.id === id)) return
      mutate(() => {
        data.repositories = data.repositories.filter(repository => repository.id !== id)
        if (data.activeRepositoryId === id) data.activeRepositoryId = data.repositories[0]?.id ?? null
        for (const key of Object.keys(data.reviewStatuses)) if ((JSON.parse(key) as string[])[0] === id) delete data.reviewStatuses[key]
        cleanReferences()
      })
    },
    selectRepository(id: string) {
      if (!data.repositories.some(repository => repository.id === id)) throw new WorkspaceActionError('登録済みのリポジトリを選択してください。')
      beginChange()
      if (!write(storage.session, viewKey(activeProfile), id)) throw new WorkspaceActionError(storageError)
      data.activeRepositoryId = id
    },
    toggleSaved(articleId: string, reference?: SavedReportReference) {
      articleIdInput(articleId)
      const removing = data.savedIds.includes(articleId)
      if (!removing && data.savedIds.length >= 5000) throw new WorkspaceActionError('保存できる記事は5000件までです。')
      mutate(() => {
        if (!removing) keepReference(articleId, reference)
        data.savedIds = removing ? data.savedIds.filter(id => id !== articleId) : [...data.savedIds, articleId]
        cleanReferences()
      })
    },
    addComment(articleId: string, body: string, reference?: SavedReportReference) {
      articleIdInput(articleId)
      const text = inputText(body.replace(/\r\n?/gu, '\n'), 2000, 'コメント')
      if (data.comments.length >= 500) throw new WorkspaceActionError('コメントは500件まで保存できます。')
      const comment: FeedComment = { id: `comment:${localId()}`, articleId, body: text,
        authorId: user?.id ?? 'guest', authorName: user?.displayName ?? 'ゲスト', createdAt: new Date().toISOString() }
      mutate(() => { keepReference(articleId, reference); data.comments.push(comment) })
    },
    deleteComment(id: string) {
      const comment = data.comments.find(item => item.id === id)
      if (!comment || comment.authorId !== (user?.id ?? 'guest')) throw new WorkspaceActionError('自分のコメントだけ削除できます。')
      mutate(() => { data.comments = data.comments.filter(item => item.id !== id); cleanReferences() })
    },
    setReviewStatus(repositoryId: string, articleId: string, status: ReviewStatus, reference?: SavedReportReference) {
      articleIdInput(articleId)
      if (!data.repositories.some(repository => repository.id === repositoryId)) throw new WorkspaceActionError('登録済みのリポジトリを選択してください。')
      if (!statuses.includes(status)) throw new WorkspaceActionError('確認状態が不正です。')
      const key = reviewKey(repositoryId, articleId)
      if (status !== 'unreviewed' && !(key in data.reviewStatuses) && Object.keys(data.reviewStatuses).length >= 5000) throw new WorkspaceActionError('確認状態は5000件まで保存できます。')
      mutate(() => {
        if (status === 'unreviewed') delete data.reviewStatuses[key]
        else { keepReference(articleId, reference); data.reviewStatuses[key] = status }
        cleanReferences()
      })
    },
    getReviewStatus(repositoryId: string, articleId: string): ReviewStatus {
      return data.reviewStatuses[reviewKey(repositoryId, articleId)] ?? 'unreviewed'
    },
    reloadLatest() {
      beginChange()
      if (activeProfile !== null) {
        const profile = readProfile(activeProfile)
        if (!profile) throw new WorkspaceActionError('最新の保存内容を読み込めませんでした。元データは変更していません。')
        user = profile.user; data = profile.data
      } else {
        const result = read(storage.session, guestKey)
        if (result.kind === 'failed') throw new WorkspaceActionError('最新の保存内容を読み込めませんでした。元データは変更していません。')
        if (result.kind === 'missing') guest = emptyData()
        else if (isRecord(result.value) && result.value.version === 1) {
          const restored = salvageData(result.value.data, 'guest')
          guest = restored.data
          if (restored.recovered) block(storage.session, guestKey, result.raw, { version: 1, data: guest })
        } else { block(storage.session, guestKey, result.raw); throw new WorkspaceActionError(recoveryMessage) }
        applyView(guest, null)
        data = guest
      }
    },
    notifyStorageChange(key: string | null) {
      if (activeProfile !== null && (key === null || key === profileKey(activeProfile))) {
        conflict = true
        storageError = '別のタブで保存内容が変更されました。「最新を読み込む」で反映してください。'
      }
    },
    exportRecovery(): string {
      return JSON.stringify({ exportedAt: new Date().toISOString(), workspace: snapshot(),
        originals: Array.from(recovery.values(), ({ key, raw }) => ({ key, raw })) }, null, 2)
    },
    resetRecovery() {
      beginChange()
      for (const record of recovery.values()) {
        // Archive raw bytes before any overwrite; a quota failure leaves the
        // original untouched. Unknown versions are never interpreted as v1.
        const backupKey = `${record.key}:recovery:${localId()}`
        try {
          if (!record.target) throw new WorkspaceActionError('Storage unavailable')
          if (record.target.getItem(record.key) !== record.raw) throw new WorkspaceActionError('Changed since read')
          record.target.setItem(backupKey, record.raw)
          if (record.replacement !== undefined) {
            if (!write(record.target, record.key, record.replacement)) throw new WorkspaceActionError('Write failed')
          } else record.target.removeItem(record.key)
        } catch { storageError = '元データを退避できないため保存を再開していません。エクスポート後、保存領域を確認してください。'; throw new WorkspaceActionError(storageError) }
        recovery.delete(record.key)
      }
      if (activeProfile !== null) {
        const profile = readProfile(activeProfile)
        if (profile) { user = profile.user; data = profile.data }
      }
      storageNotice = '元データのバックアップを残し、読み込めたデータで保存を再開しました。'
    },
  }
}
