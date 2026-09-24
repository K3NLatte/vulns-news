import { parseRepositoryUrl } from './feed'
import type {
  AddRepositoryResult, FeedComment, ReviewStatus, WorkspaceData,
  WorkspaceSnapshot, WorkspaceUser,
} from '../types/workspace'

export interface WorkspaceStorage {
  session: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null
  local: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null
}

const guestKey = 'vulns-news:workspace:guest:v1'
const activeKey = 'vulns-news:workspace:active:v1'
const profileKey = (name: string) => `vulns-news:workspace:profile:v1:${encodeURIComponent(name)}`
const statuses: ReviewStatus[] = ['unreviewed', 'investigating', 'resolved', 'not-affected']
const emptyData = (): WorkspaceData => ({ repositories: [], activeRepositoryId: null, savedIds: [], comments: [], reviewStatuses: {} })
const copy = <T>(value: T): T => structuredClone(value)
const normalizedName = (name: string) => name.normalize('NFKC').toLocaleLowerCase('ja-JP')
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
const isText = (value: unknown, limit: number): value is string => typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\u0000-\u0008\u000b-\u001f\u007f]/u.test(value)
const isId = (value: unknown): value is string => isText(value, 200) && !/\s/u.test(value)
const reviewKey = (repositoryId: string, articleId: string) => JSON.stringify([repositoryId, articleId])

function inputText(value: string, limit: number, label: string): string {
  const text = value.trim()
  if (!isText(text, limit)) throw new Error(`${label}は1〜${limit}文字で入力してください。`)
  return text
}

function articleIdInput(value: string): string {
  if (!isId(value)) throw new Error('記事IDが不正です。')
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
    if (!parsed.ok || parsed.url !== repository.url || parsed.label !== repository.label) return false
  }
  if (new Set(repositories.map(repository => repository.id)).size !== repositories.length
    || new Set(repositories.map(repository => repository.url.toLowerCase())).size !== repositories.length) return false
  if (value.activeRepositoryId !== null && !repositories.some(repository => repository.id === value.activeRepositoryId)) return false
  if (!value.savedIds.every(isId) || new Set(value.savedIds).size !== value.savedIds.length) return false
  for (const comment of value.comments) {
    if (!isRecord(comment) || !isId(comment.id) || !isId(comment.articleId) || comment.authorId !== authorId
      || !isText(comment.authorName, 40) || !isText(comment.body, 2000)
      || typeof comment.createdAt !== 'string' || !Number.isFinite(Date.parse(comment.createdAt))) return false
  }
  if (new Set(value.comments.map(comment => comment.id)).size !== value.comments.length) return false
  for (const [key, status] of Object.entries(value.reviewStatuses)) {
    if (!statuses.includes(status as ReviewStatus)) return false
    let parts: unknown
    try { parts = JSON.parse(key) } catch { return false }
    if (!Array.isArray(parts) || parts.length !== 2 || !isId(parts[0]) || !isId(parts[1])
      || reviewKey(parts[0], parts[1]) !== key || !repositories.some(repository => repository.id === parts[0])) return false
  }
  return true
}

function browserStorage(name: 'sessionStorage' | 'localStorage'): Storage | null {
  try { return typeof window === 'undefined' ? null : window[name] } catch { return null }
}

/** Browser-local profile adapter. No authentication, passwords, tokens, or network requests. */
export function createWorkspaceStore(storage: WorkspaceStorage = {
  session: browserStorage('sessionStorage'), local: browserStorage('localStorage'),
}) {
  let storageError = ''
  const read = (target: WorkspaceStorage['session'], key: string): unknown => {
    try {
      if (!target) throw new Error('Storage unavailable')
      const text = target.getItem(key)
      if (text === null) return null
      if (text.length > 2_000_000) throw new Error('Stored data too large')
      return JSON.parse(text)
    } catch {
      storageError = '保存データを読み込めませんでした。変更は現在の画面内だけで保持される場合があります。'
      return null
    }
  }
  const write = (target: WorkspaceStorage['session'], key: string, value: unknown): boolean => {
    try {
      if (!target) throw new Error('Storage unavailable')
      target.setItem(key, JSON.stringify(value))
      return true
    } catch {
      storageError = 'このブラウザーに保存できません。変更は現在の画面内だけで保持されます。'
      return false
    }
  }
  const remove = (target: WorkspaceStorage['session'], key: string) => {
    try {
      if (!target) throw new Error('Storage unavailable')
      target.removeItem(key)
    } catch { storageError = 'セッションの変更を保存できませんでした。このタブを閉じてから開き直してください。' }
  }
  const invalidStoredData = () => { storageError = '保存データの形式が不正なため、そのデータを読み込まずに開始しました。' }
  const storedGuest = read(storage.session, guestKey)
  let guest = emptyData()
  if (storedGuest !== null) {
    if (isRecord(storedGuest) && storedGuest.version === 1 && validateData(storedGuest.data, 'guest')) guest = copy(storedGuest.data)
    else invalidStoredData()
  }
  const profiles = new Map<string, { user: WorkspaceUser; data: WorkspaceData }>()
  const readProfile = (name: string) => {
    const cached = profiles.get(name)
    if (cached) return cached
    const stored = read(storage.local, profileKey(name))
    if (stored === null) return null
    if (!isRecord(stored) || stored.version !== 1 || !validateUser(stored.user)
      || normalizedName(stored.user.displayName) !== name || !validateData(stored.data, stored.user.id)) {
      invalidStoredData()
      return null
    }
    const profile = { user: copy(stored.user), data: copy(stored.data) }
    profiles.set(name, profile)
    return profile
  }
  let user: WorkspaceUser | null = null
  let activeProfile: string | null = null
  let data = guest
  const active = read(storage.session, activeKey)
  if (active !== null) {
    if (isRecord(active) && active.version === 1 && typeof active.name === 'string' && active.name.length <= 40) {
      const profile = readProfile(active.name)
      if (profile) { user = profile.user; data = profile.data; activeProfile = active.name }
      else remove(storage.session, activeKey)
    } else { invalidStoredData(); remove(storage.session, activeKey) }
  }

  const persist = () => {
    if (user && activeProfile !== null) {
      profiles.set(activeProfile, { user, data })
      return write(storage.local, profileKey(activeProfile), { version: 1, user, data })
    }
    guest = data
    return write(storage.session, guestKey, { version: 1, data: guest })
  }
  const beginChange = () => { storageError = '' }
  const snapshot = (): WorkspaceSnapshot => copy({ ...data, user, storageError })

  return {
    snapshot,
    login(displayName: string) {
      const name = inputText(displayName, 40, '表示名').replace(/\s+/gu, ' ')
      if (/[\r\n\t]/u.test(displayName)) throw new Error('表示名には改行やタブを使用できません。')
      beginChange()
      const key = normalizedName(name)
      let profile = readProfile(key)
      const isNew = profile === null
      if (!profile) {
        const newUser = { id: `user:${crypto.randomUUID()}`, displayName: name }
        const transferred = copy(guest)
        transferred.comments = transferred.comments.map(comment => ({ ...comment, authorId: newUser.id, authorName: name }))
        profile = { user: newUser, data: transferred }
      }
      user = profile.user
      data = profile.data
      activeProfile = key
      const saved = persist()
      if (saved) {
        write(storage.session, activeKey, { version: 1, name: key })
        if (isNew && write(storage.session, guestKey, { version: 1, data: emptyData() })) guest = emptyData()
      } else remove(storage.session, activeKey)
    },
    logout() {
      beginChange()
      remove(storage.session, activeKey)
      user = null
      activeProfile = null
      data = guest
    },
    addRepository(url: string): AddRepositoryResult {
      const parsed = parseRepositoryUrl(url)
      if (!parsed.ok) return parsed
      if (data.repositories.some(repository => repository.url.toLowerCase() === parsed.url.toLowerCase())) {
        return { ok: false, message: 'このリポジトリは登録済みです。' }
      }
      if (data.repositories.length >= 20) return { ok: false, message: 'リポジトリは20件まで登録できます。' }
      beginChange()
      const repository = { id: `repo:${crypto.randomUUID()}`, url: parsed.url, label: parsed.label }
      data.repositories.push(repository)
      data.activeRepositoryId = repository.id
      persist()
      return { ok: true, repository: copy(repository) }
    },
    removeRepository(id: string) {
      if (!data.repositories.some(repository => repository.id === id)) return
      beginChange()
      data.repositories = data.repositories.filter(repository => repository.id !== id)
      if (data.activeRepositoryId === id) data.activeRepositoryId = data.repositories[0]?.id ?? null
      for (const key of Object.keys(data.reviewStatuses)) {
        if ((JSON.parse(key) as string[])[0] === id) delete data.reviewStatuses[key]
      }
      persist()
    },
    selectRepository(id: string) {
      if (!data.repositories.some(repository => repository.id === id)) throw new Error('登録済みのリポジトリを選択してください。')
      beginChange()
      data.activeRepositoryId = id
      persist()
    },
    toggleSaved(articleId: string) {
      articleIdInput(articleId)
      if (!data.savedIds.includes(articleId) && data.savedIds.length >= 5000) throw new Error('保存できる記事は5000件までです。')
      beginChange()
      data.savedIds = data.savedIds.includes(articleId) ? data.savedIds.filter(id => id !== articleId) : [...data.savedIds, articleId]
      persist()
    },
    addComment(articleId: string, body: string) {
      articleIdInput(articleId)
      const text = inputText(body.replace(/\r\n?/gu, '\n'), 2000, 'コメント')
      if (data.comments.length >= 500) throw new Error('コメントは500件まで保存できます。')
      beginChange()
      const comment: FeedComment = {
        id: `comment:${crypto.randomUUID()}`, articleId, body: text,
        authorId: user?.id ?? 'guest', authorName: user?.displayName ?? 'ゲスト', createdAt: new Date().toISOString(),
      }
      data.comments.push(comment)
      persist()
    },
    deleteComment(id: string) {
      const comment = data.comments.find(item => item.id === id)
      if (!comment || comment.authorId !== (user?.id ?? 'guest')) throw new Error('自分のコメントだけ削除できます。')
      beginChange()
      data.comments = data.comments.filter(item => item.id !== id)
      persist()
    },
    setReviewStatus(repositoryId: string, articleId: string, status: ReviewStatus) {
      articleIdInput(articleId)
      if (!data.repositories.some(repository => repository.id === repositoryId)) throw new Error('登録済みのリポジトリを選択してください。')
      if (!statuses.includes(status)) throw new Error('確認状態が不正です。')
      const key = reviewKey(repositoryId, articleId)
      if (!(key in data.reviewStatuses) && Object.keys(data.reviewStatuses).length >= 5000) throw new Error('確認状態は5000件まで保存できます。')
      beginChange()
      if (status === 'unreviewed') delete data.reviewStatuses[key]
      else data.reviewStatuses[key] = status
      persist()
    },
    getReviewStatus(repositoryId: string, articleId: string): ReviewStatus {
      return data.reviewStatuses[reviewKey(repositoryId, articleId)] ?? 'unreviewed'
    },
  }
}
