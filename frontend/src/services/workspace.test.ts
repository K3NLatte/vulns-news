import { afterEach, describe, expect, it, vi } from 'vitest'
import { effectScope, reactive } from 'vue'
import { useWorkspace } from '../composables/useWorkspace'
import { createWorkspaceStore, type WorkspaceStorage } from './workspace'
import { createSubmittedReport, getSavedReportItems } from './reports'
import { localId } from '../utils/localId'
import type { ReviewStatus } from '../types/workspace'

class MemoryStorage {
  values = new Map<string, string>()
  getItem(key: string) { return this.values.get(key) ?? null }
  setItem(key: string, value: string) { this.values.set(key, value) }
  removeItem(key: string) { this.values.delete(key) }
}
const makeStorage = () => ({ session: new MemoryStorage(), local: new MemoryStorage() })
const guestKey = 'vulns-news:workspace:guest:v1'
const activeKey = 'vulns-news:workspace:active:v1'
const profileKey = (name: string) => `vulns-news:workspace:profile:v1:${encodeURIComponent(name)}`
const createRepository = (store: ReturnType<typeof createWorkspaceStore>, name = 'frontend') => {
  const result = store.addRepository(`https://github.com/example/${name}`)
  if (!result.ok) throw new Error(result.message)
  return result.repository
}

describe('workspace persistence', () => {
  it('restores guest repositories, saves, comments and repository-specific review states in the same session', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    const frontend = createRepository(store)
    const backend = createRepository(store, 'backend')
    store.selectRepository(frontend.id)
    store.toggleSaved('demo-001')
    store.addComment('demo-001', 'プレビューの公開設定を確認します。')
    store.setReviewStatus(frontend.id, 'demo-001', 'investigating')
    store.setReviewStatus(backend.id, 'demo-001', 'not-affected')
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot()).toEqual(store.snapshot())
    expect(restored.snapshot().comments[0]?.authorId).toBe('guest')
    expect(restored.getReviewStatus(frontend.id, 'demo-001')).toBe('investigating')
    expect(restored.getReviewStatus(backend.id, 'demo-001')).toBe('not-affected')
    expect(storage.local.values.size).toBe(0)
  })

  it('migrates guest additions into the first profile and restores the signed-in session after reload', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    const repository = createRepository(store)
    store.toggleSaved('demo-001')
    store.addComment('demo-001', '修正版の適用を確認中です。')
    store.setReviewStatus(repository.id, 'demo-001', 'investigating')
    store.login('Alice')
    const signedIn = store.snapshot()
    expect(signedIn.user?.displayName).toBe('Alice')
    expect(signedIn.repositories).toHaveLength(1)
    expect(signedIn.comments[0]?.authorId).toBe(signedIn.user?.id)
    expect(signedIn.comments[0]?.authorName).toBe('Alice')
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot()).toEqual(signedIn)
    restored.logout()
    expect(restored.snapshot().user).toBeNull()
    expect(restored.snapshot().savedIds).toEqual([])
    expect(restored.snapshot().comments).toEqual([])
    expect(createWorkspaceStore(storage).snapshot().user).toBeNull()
    restored.login('ALICE')
    expect(restored.snapshot().user?.id).toBe(signedIn.user?.id)
    expect(restored.snapshot().savedIds).toEqual(['demo-001'])
  })

  it('isolates profiles and does not transfer signed-in content to a different profile', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login('Alice')
    store.toggleSaved('alice-only')
    store.addComment('demo-001', 'Aliceのコメント')
    store.logout()
    store.toggleSaved('guest-addition')
    store.login('Bob')
    expect(store.snapshot().savedIds).toEqual(['guest-addition'])
    expect(store.snapshot().comments).toEqual([])
    store.addComment('demo-001', 'Bobのコメント')
    const bobComment = store.snapshot().comments[0]!
    store.logout()
    store.login('Alice')
    expect(store.snapshot().savedIds).toEqual(['alice-only'])
    expect(store.snapshot().comments.map(comment => comment.body)).toEqual(['Aliceのコメント'])
    expect(() => store.deleteComment(bobComment.id)).toThrow('自分のコメント')
  })

  it('preserves guest work separately when entering an existing profile', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login('Alice')
    store.toggleSaved('account-only')
    store.logout()
    store.toggleSaved('guest-only')
    store.login('Alice')
    expect(store.snapshot().savedIds).toEqual(['account-only'])
    store.logout()
    expect(store.snapshot().savedIds).toEqual(['guest-only'])
  })

  it('does not sign another browser session in just because the profile exists locally', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login('Alice')
    store.toggleSaved('account-only')
    const otherSession = createWorkspaceStore({ local: storage.local, session: new MemoryStorage() })
    expect(otherSession.snapshot().user).toBeNull()
    expect(otherSession.snapshot().savedIds).toEqual([])
  })

  it('normalizes repository URLs, prevents duplicates and cleans review states on removal', () => {
    const store = createWorkspaceStore(makeStorage())
    const first = createRepository(store)
    const second = createRepository(store, 'backend')
    expect(store.addRepository('https://github.com/EXAMPLE/FRONTEND.git/').ok).toBe(false)
    expect(store.addRepository('https://github.com.evil.example/owner/repo').ok).toBe(false)
    store.setReviewStatus(second.id, 'demo-001', 'resolved')
    store.removeRepository(second.id)
    expect(store.snapshot().activeRepositoryId).toBe(first.id)
    expect(store.getReviewStatus(second.id, 'demo-001')).toBe('unreviewed')
    store.removeRepository(first.id)
    expect(store.snapshot().activeRepositoryId).toBeNull()
    expect(() => store.selectRepository('missing')).toThrow('登録済み')
    expect(() => store.setReviewStatus('missing', 'demo-001', 'resolved')).toThrow('登録済み')
  })

  it('validates names, comments and status values while preserving literal text', () => {
    const store = createWorkspaceStore(makeStorage())
    expect(() => store.login(' ')).toThrow('表示名')
    expect(() => store.login('a'.repeat(41))).toThrow('40')
    expect(() => store.login('a\nb')).toThrow('改行')
    expect(() => store.addComment('demo-001', ' ')).toThrow('コメント')
    expect(() => store.addComment('demo-001', 'a'.repeat(2001))).toThrow('2000')
    expect(() => store.addComment('bad id', 'text')).toThrow('記事ID')
    const text = '<script>alert(1)</script>\n内容を確認します。'
    store.addComment('demo-001', text)
    expect(store.snapshot().comments[0]?.body).toBe(text)
    const repository = createRepository(store)
    expect(() => store.setReviewStatus(repository.id, 'demo-001', 'invalid' as ReviewStatus)).toThrow('確認状態')
    store.deleteComment(store.snapshot().comments[0]!.id)
    expect(store.snapshot().comments).toEqual([])
  })

  it('toggles saves and returns unresolved reviews to their default', () => {
    const store = createWorkspaceStore(makeStorage())
    const repository = createRepository(store)
    store.toggleSaved('demo-001')
    store.toggleSaved('demo-001')
    expect(store.snapshot().savedIds).toEqual([])
    store.setReviewStatus(repository.id, 'demo-001', 'investigating')
    store.setReviewStatus(repository.id, 'demo-001', 'unreviewed')
    expect(store.snapshot().reviewStatuses).toEqual({})
  })

  it('ignores corrupt JSON and invalid stored structures without crashing', () => {
    const storage = makeStorage()
    storage.session.setItem(guestKey, '{broken')
    expect(createWorkspaceStore(storage).snapshot().storageError).not.toBe('')
    storage.session.setItem(guestKey, JSON.stringify({ version: 1, data: { savedIds: 'not-an-array' } }))
    const store = createWorkspaceStore(storage)
    expect(store.snapshot().savedIds).toEqual([])
    expect(store.snapshot().storageError).toContain('形式')
  })

  it('rejects stored comments attributed to a different profile', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login('Alice')
    store.addComment('demo-001', '確認中')
    const key = profileKey('alice')
    const stored = JSON.parse(storage.local.getItem(key)!)
    stored.data.comments[0].authorId = 'another-user'
    storage.local.setItem(key, JSON.stringify(stored))
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot().user?.displayName).toBe('Alice')
    expect(restored.snapshot().comments).toEqual([])
    expect(restored.snapshot().storageError).toContain('形式')
  })

  it('continues in memory when storage is unavailable and preserves guest data on a failed migration', () => {
    const store = createWorkspaceStore({ session: null, local: null })
    store.toggleSaved('guest-only')
    store.login('Alice')
    store.toggleSaved('account-only')
    expect(store.snapshot().storageNotice).not.toBe('')
    store.logout()
    expect(store.snapshot().savedIds).toEqual(['guest-only'])
    expect(store.snapshot().user).toBeNull()
  })

  it('handles quota failures without losing the active in-memory state', () => {
    const storage = makeStorage()
    const failing: WorkspaceStorage = {
      session: storage.session,
      local: { getItem: () => null, setItem: () => { throw new Error('Quota exceeded') }, removeItem: () => {} },
    }
    const store = createWorkspaceStore(failing)
    store.addComment('demo-001', '保存状態を確認')
    expect(() => store.login('Alice')).toThrow('アカウントを保存できません')
    expect(store.snapshot().user).toBeNull()
    expect(store.snapshot().comments).toHaveLength(1)
    expect(store.snapshot().storageError).toContain('保存できません')
    store.logout()
    expect(store.snapshot().comments[0]?.authorId).toBe('guest')
  })

  it('returns defensive snapshots so a consumer cannot silently change persisted state', () => {
    const store = createWorkspaceStore(makeStorage())
    createRepository(store)
    store.snapshot().repositories[0]!.url = 'https://evil.example/'
    expect(store.snapshot().repositories[0]?.url).toBe('https://github.com/example/frontend')
  })

  it('updates composable refs after acknowledged async operations', async () => {
    const workspace = useWorkspace(makeStorage())
    const added = await workspace.addRepository('https://github.com/example/frontend')
    if (!added.ok) throw new Error(added.message)
    await workspace.toggleSaved('demo-001')
    await workspace.addComment('demo-001', '確認中')
    await workspace.setReviewStatus(added.value.id, 'demo-001', 'investigating')
    expect(workspace.repositories.value).toHaveLength(1)
    expect(workspace.activeRepositoryId.value).toBe(added.value.id)
    expect(workspace.savedIds.value).toEqual(['demo-001'])
    expect(workspace.comments.value).toHaveLength(1)
    expect(workspace.getReviewStatus(added.value.id, 'demo-001')).toBe('investigating')
    await workspace.login('Alice')
    expect(workspace.user.value?.displayName).toBe('Alice')
    await workspace.logout()
    expect(workspace.user.value).toBeNull()
    expect(workspace.comments.value).toEqual([])
  })

  it('keeps guest work when the signed-in session marker cannot be saved', () => {
    const storage = makeStorage()
    const session = {
      getItem: (key: string) => storage.session.getItem(key),
      removeItem: (key: string) => storage.session.removeItem(key),
      setItem: (key: string, value: string) => {
        if (key === 'vulns-news:workspace:active:v1') throw new Error('Session write failed')
        storage.session.setItem(key, value)
      },
    }
    const store = createWorkspaceStore({ local: storage.local, session })
    store.toggleSaved('guest-work')
    expect(() => store.login('Alice')).toThrow('ログイン状態を保存できません')
    expect(store.snapshot().user).toBeNull()
    expect(storage.local.getItem(profileKey('alice'))).toBeNull()
    expect(store.snapshot().storageError).not.toBe('')
    expect(createWorkspaceStore(storage).snapshot().savedIds).toEqual(['guest-work'])
    store.logout()
    expect(store.snapshot().savedIds).toEqual(['guest-work'])
  })

  it('does not replace an existing profile when reading it temporarily fails', () => {
    const storage = makeStorage()
    const existing = createWorkspaceStore(storage)
    existing.login('Alice')
    existing.toggleSaved('account-work')
    existing.logout()
    const savedProfile = storage.local.getItem(profileKey('alice'))
    let failRead = true
    const local = {
      getItem: (key: string) => {
        if (failRead) throw new Error('Read unavailable')
        return storage.local.getItem(key)
      },
      setItem: (key: string, value: string) => storage.local.setItem(key, value),
      removeItem: (key: string) => storage.local.removeItem(key),
    }
    const store = createWorkspaceStore({ local, session: storage.session })
    store.toggleSaved('guest-work')
    expect(() => store.login('Alice')).toThrow('読み込めない')
    expect(storage.local.getItem(profileKey('alice'))).toBe(savedProfile)
    expect(store.snapshot().user).toBeNull()
    expect(store.snapshot().savedIds).toEqual(['guest-work'])
    failRead = false
    store.login('Alice')
    expect(store.snapshot().savedIds).toEqual(['account-work'])
  })

  it.each(['{broken', 'null', '{"version":1,"user":null,"data":{}}'])(
    'does not overwrite an invalid profile: %s', (invalidProfile) => {
      const storage = makeStorage()
      storage.local.setItem(profileKey('alice'), invalidProfile)
      const store = createWorkspaceStore(storage)
      expect(() => store.login('Alice')).toThrow('読み込めない')
      expect(storage.local.getItem(profileKey('alice'))).toBe(invalidProfile)
      expect(store.snapshot().user).toBeNull()
    },
  )

  it('restores a valid display name even when normalization expands it beyond 40 characters', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login('\uFB03'.repeat(14))
    store.toggleSaved('account-work')
    expect(createWorkspaceStore(storage).snapshot()).toEqual(store.snapshot())
  })

  it('rejects malformed Unicode in names and stored active profile keys without crashing', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    expect(() => store.login('\uD800')).toThrow('表示名')
    storage.session.setItem('vulns-news:workspace:active:v1', JSON.stringify({ version: 1, name: '\uD800' }))
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot().user).toBeNull()
    expect(restored.snapshot().storageError).not.toBe('')
    store.login('安全な名前😀')
    expect(createWorkspaceStore(storage).snapshot().user?.displayName).toBe('安全な名前😀')
  })

  it('preserves the last readable save when escaped comments exceed the storage read limit', () => {
    const storage = makeStorage()
    const data = {
      repositories: [], activeRepositoryId: null, savedIds: [], reviewStatuses: {},
      comments: [] as Array<{ id: string; articleId: string; authorId: string; authorName: string; body: string; createdAt: string }>,
    }
    const comment = {
      id: 'comment:000', articleId: 'demo-001', authorId: 'guest', authorName: 'ゲスト',
      body: '\\'.repeat(2000), createdAt: '2026-09-25T00:00:00.000Z',
    }
    const envelopeSize = JSON.stringify({ version: 1, data }).length
    const entrySize = JSON.stringify(comment).length + 1
    const count = Math.floor((2_000_000 - envelopeSize) / entrySize)
    data.comments = Array.from({ length: count }, (_, index) => ({ ...comment, id: `comment:${String(index).padStart(3, '0')}` }))
    const lastSaved = JSON.stringify({ version: 1, data })
    expect(lastSaved.length).toBeLessThanOrEqual(2_000_000)
    expect(count).toBeLessThan(500)
    storage.session.setItem(guestKey, lastSaved)
    const store = createWorkspaceStore(storage)
    expect(store.snapshot().comments).toHaveLength(count)
    expect(() => store.addComment('demo-001', '\\'.repeat(2000))).toThrow('保存容量')
    expect(store.snapshot().comments).toHaveLength(count)
    expect(store.snapshot().storageError).toContain('保存容量')
    expect(storage.session.getItem(guestKey)).toBe(lastSaved)
    expect(createWorkspaceStore(storage).snapshot().comments).toHaveLength(count)
  })

  it.each([false, true])('restores mixed-case repository labels with canonical URLs (profile: %s)', (signedIn) => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    if (signedIn) store.login('Alice')
    const result = store.addRepository('https://github.com/Example/Project')
    if (!result.ok) throw new Error(result.message)
    expect(result.repository.url).toBe('https://github.com/example/project')
    expect(result.repository.label).toBe('Example/Project')
    store.toggleSaved('keep-this-save')
    expect(createWorkspaceStore(storage).snapshot()).toEqual(store.snapshot())
  })

  it('migrates previously stored mixed-case URLs while preserving their labels and workspace data', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.addRepository('https://github.com/Example/Project')
    store.toggleSaved('keep-this-save')
    const stored = JSON.parse(storage.session.getItem(guestKey)!)
    stored.data.repositories[0].url = 'https://github.com/Example/Project'
    storage.session.setItem(guestKey, JSON.stringify(stored))
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot().storageError).toBe('')
    expect(restored.snapshot().savedIds).toEqual(['keep-this-save'])
    expect(restored.snapshot().repositories[0]).toMatchObject({
      url: 'https://github.com/example/project', label: 'Example/Project',
    })
    restored.toggleSaved('another-save')
    expect(JSON.parse(storage.session.getItem(guestKey)!).data.repositories[0].url).toBe('https://github.com/example/project')
  })

  it.each(['other/project', 'Example/Project/', 'Example/Project.git', 'Example/Project\n'])(
    'rejects a stored label that is not the same repository: %s', (label) => {
      const storage = makeStorage()
      const store = createWorkspaceStore(storage)
      store.addRepository('https://github.com/Example/Project')
      const stored = JSON.parse(storage.session.getItem(guestKey)!)
      stored.data.repositories[0].label = label
      storage.session.setItem(guestKey, JSON.stringify(stored))
      const restored = createWorkspaceStore(storage)
      expect(restored.snapshot().repositories).toEqual([])
      expect(restored.snapshot().storageError).toContain('形式')
    },
  )
})

it('preserves a newer profile save from another tab instead of overwriting it with stale state', () => {
  const storage = makeStorage()
  const first = createWorkspaceStore(storage)
  first.login('Alice')
  first.toggleSaved('original')
  const second = createWorkspaceStore({ local: storage.local, session: new MemoryStorage() })
  second.login('Alice')
  first.toggleSaved('from-first-tab')
  const newerSave = storage.local.getItem(profileKey('alice'))

  expect(() => second.toggleSaved('from-second-tab')).toThrow('別のタブ')

  expect(storage.local.getItem(profileKey('alice'))).toBe(newerSave)
  expect(second.snapshot().savedIds).toEqual(['original'])
  expect(second.snapshot().storageError).toContain('別のタブ')
  expect(createWorkspaceStore(storage).snapshot().savedIds).toEqual(['original', 'from-first-tab'])
})

it('preserves newer profile data when re-entering a cached profile changed in another tab', () => {
  const storage = makeStorage()
  const first = createWorkspaceStore(storage)
  first.login('Alice')
  first.toggleSaved('original')
  first.logout()
  const second = createWorkspaceStore({ local: storage.local, session: new MemoryStorage() })
  second.login('Alice')
  second.toggleSaved('other-tab-save')
  const newerSave = storage.local.getItem(profileKey('alice'))

  first.login('Alice')

  expect(storage.local.getItem(profileKey('alice'))).toBe(newerSave)
  expect(first.snapshot().storageError).toBe('')
  expect(first.snapshot().savedIds).toEqual(['original', 'other-tab-save'])
  first.toggleSaved('after-relogin')
  const restored = createWorkspaceStore(storage)
  expect(restored.snapshot().user?.displayName).toBe('Alice')
  expect(restored.snapshot().savedIds).toEqual(['original', 'other-tab-save', 'after-relogin'])
})


describe('saved submission references', () => {
  const reference = { input: 'CVE-2026-12345', createdAt: '2026-09-25T03:00:00.000Z' }
  const article = createSubmittedReport(reference.input, 'cve', reference.createdAt)

  it('restores saved submitted content in a new session without trusting serialized report facts', () => {
    const storage = makeStorage()
    const first = createWorkspaceStore(storage)
    first.login('Alice')
    first.toggleSaved(article.id, reference)
    const otherSession = createWorkspaceStore({ local: storage.local, session: new MemoryStorage() })
    otherSession.login('Alice')
    const restored = getSavedReportItems(otherSession.snapshot().savedReportReferences)
    expect(restored).toHaveLength(1)
    expect(restored[0]).toMatchObject({ id: article.id, cvss: null, assessment: 'unverified', repositoryAnalysis: 'pending' })
    expect(otherSession.snapshot().savedIds).toEqual([article.id])
  })

  it('isolates reference bookmarks between profiles and removes them with the bookmark', () => {
    const store = createWorkspaceStore(makeStorage())
    store.login('Alice')
    store.toggleSaved(article.id, reference)
    store.logout()
    expect(store.snapshot().savedReportReferences).toEqual({})
    store.login('Bob')
    expect(store.snapshot().savedReportReferences).toEqual({})
    store.login('Alice')
    expect(store.snapshot().savedReportReferences[article.id]).toEqual(reference)
    store.toggleSaved(article.id)
    expect(store.snapshot().savedReportReferences).toEqual({})
    expect(store.snapshot().savedIds).toEqual([])
  })

  it('transfers guest references into a new profile and exposes them through the composable', async () => {
    const workspace = useWorkspace(makeStorage())
    await workspace.toggleSaved(article.id, reference)
    await workspace.login('Alice')
    expect(workspace.savedReportReferences.value[article.id]).toEqual(reference)
    await workspace.logout()
    expect(workspace.savedReportReferences.value).toEqual({})
  })

  it('rejects a mismatched reference before mutating saved IDs', () => {
    const store = createWorkspaceStore(makeStorage())
    expect(() => store.toggleSaved('demo-001', reference)).toThrow('記事の情報')
    expect(store.snapshot().savedIds).toEqual([])
    expect(() => store.toggleSaved(article.id, { ...reference, createdAt: 'invalid' })).toThrow('記事の情報')
    expect(() => store.toggleSaved(article.id, { ...reference, input: 'javascript:alert(1)' })).toThrow('記事の情報')
    expect(store.snapshot().savedReportReferences).toEqual({})
  })

  it('rejects forged stored references unrelated to saved IDs', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.toggleSaved(article.id, reference)
    const state = JSON.parse(storage.session.getItem(guestKey)!)
    state.data.savedReportReferences['submitted-CVE-2026-99999'] = { ...reference, input: 'CVE-2026-99999' }
    storage.session.setItem(guestKey, JSON.stringify(state))
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot().storageError).toContain('形式')
    expect(restored.snapshot().savedIds).toEqual([article.id])
    expect(restored.snapshot().savedReportReferences['submitted-CVE-2026-99999']).toBeUndefined()
  })
})


it('accepts a reactive saved reference without leaking the caller object into persisted state', () => {
  const store = createWorkspaceStore(makeStorage())
  const reference = reactive({ input: 'CVE-2026-12345', createdAt: '2026-09-25T03:00:00.000Z' })
  const item = createSubmittedReport(reference.input, 'cve', reference.createdAt)
  store.toggleSaved(item.id, reference)
  reference.input = 'CVE-2026-99999'
  expect(store.snapshot().savedReportReferences[item.id]?.input).toBe('CVE-2026-12345')
})

describe('profile login recovery', () => {
  it('rolls back conflicted changes and reloads the newest profile without logging out', () => {
    const storage = makeStorage()
    const first = createWorkspaceStore(storage)
    first.login('Alice')
    first.toggleSaved('original')
    const second = createWorkspaceStore({ local: storage.local, session: new MemoryStorage() })
    second.login('Alice')
    second.toggleSaved('other-tab-save')
    expect(() => first.toggleSaved('rejected')).toThrow('別のタブ')
    expect(first.snapshot().savedIds).toEqual(['original'])
    expect(first.snapshot().conflict).toBe(true)
    first.reloadLatest()
    expect(first.snapshot().user?.displayName).toBe('Alice')
    expect(first.snapshot().savedIds).toEqual(['original', 'other-tab-save'])
    first.toggleSaved('retried')
    expect(createWorkspaceStore(storage).snapshot().savedIds).toEqual(['original', 'other-tab-save', 'retried'])
  })

  it('does not rewrite a clean existing profile just to log in', () => {
    const storage = makeStorage()
    const first = createWorkspaceStore(storage)
    first.login('Alice')
    first.toggleSaved('account-work')
    first.logout()
    const local = {
      getItem: (key: string) => storage.local.getItem(key),
      setItem: () => { throw new Error('Unexpected profile write') },
      removeItem: (key: string) => storage.local.removeItem(key),
    }
    const second = createWorkspaceStore({ local, session: new MemoryStorage() })
    second.login('Alice')
    expect(second.snapshot().user?.displayName).toBe('Alice')
    expect(second.snapshot().savedIds).toEqual(['account-work'])
    expect(second.snapshot().storageError).toBe('')
  })

  it('rolls back quota-failed changes and permits retry after storage recovers', () => {
    const storage = makeStorage()
    let failWrite = false
    const local = {
      getItem: (key: string) => storage.local.getItem(key),
      setItem: (key: string, value: string) => {
        if (failWrite) throw new Error('Quota exceeded')
        storage.local.setItem(key, value)
      },
      removeItem: (key: string) => storage.local.removeItem(key),
    }
    const first = createWorkspaceStore({ local, session: storage.session })
    first.login('Alice')
    failWrite = true
    expect(() => first.toggleSaved('draft')).toThrow('保存できません')
    expect(first.snapshot().savedIds).toEqual([])
    failWrite = false
    first.toggleSaved('retried')
    expect(first.snapshot().storageError).toBe('')
    expect(createWorkspaceStore(storage).snapshot().savedIds).toEqual(['retried'])
  })

  it('retries a rejected new login without duplicating or losing guest work', () => {
    const storage = makeStorage()
    let failWrite = true
    const local = {
      getItem: (key: string) => storage.local.getItem(key),
      setItem: (key: string, value: string) => {
        if (failWrite) throw new Error('Quota exceeded')
        storage.local.setItem(key, value)
      },
      removeItem: (key: string) => storage.local.removeItem(key),
    }
    const store = createWorkspaceStore({ local, session: storage.session })
    store.addComment('demo-001', '残すコメント')
    expect(() => store.login('Alice')).toThrow('アカウントを保存できません')
    expect(store.snapshot().user).toBeNull()
    expect(store.snapshot().comments[0]?.authorId).toBe('guest')
    expect(storage.session.getItem(activeKey)).toBeNull()
    expect(storage.local.getItem(profileKey('alice'))).toBeNull()

    failWrite = false
    store.login('Alice')
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot().user?.id).toBe(store.snapshot().user?.id)
    expect(restored.snapshot().comments).toHaveLength(1)
    restored.logout()
    expect(restored.snapshot().comments).toEqual([])
  })

  it.each([
    ['\u03AA\u0301', '\u0390'],
    ['T\u0308', '\u1E97'],
    ['Ａｌｉｃｅ', 'alice'],
  ])('restores and reuses canonically equivalent profile names: %s', (displayName, equivalentName) => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login(displayName)
    store.toggleSaved('account-work')
    const userId = store.snapshot().user?.id
    const marker = JSON.parse(storage.session.getItem(activeKey)!)
    expect(marker.name.normalize('NFKC').toLocaleLowerCase('ja-JP')).toBe(marker.name)

    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot()).toEqual(store.snapshot())
    restored.logout()
    restored.login(equivalentName)
    expect(restored.snapshot().user?.id).toBe(userId)
    expect(restored.snapshot().savedIds).toEqual(['account-work'])
  })

  it('restores a legacy noncanonical active key without removing its original saved record', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login('T\u0308')
    store.toggleSaved('legacy-work')
    const canonicalName = JSON.parse(storage.session.getItem(activeKey)!).name as string
    const raw = storage.local.getItem(profileKey(canonicalName))!
    const legacyName = 't\u0308'
    storage.local.removeItem(profileKey(canonicalName))
    storage.local.setItem(profileKey(legacyName), raw)
    storage.session.setItem(activeKey, JSON.stringify({ version: 1, name: legacyName }))

    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot()).toEqual(store.snapshot())
    expect(storage.local.getItem(profileKey(legacyName))).toBe(raw)
    restored.logout()
    restored.login('\u1E97')
    expect(restored.snapshot().user?.id).toBe(store.snapshot().user?.id)
    expect(restored.snapshot().savedIds).toEqual(['legacy-work'])
  })
})


describe('storage transaction and recovery boundaries', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('does not turn a tab-local repository selection into a shared data conflict', () => {
    const storage = makeStorage()
    const first = createWorkspaceStore(storage)
    first.login('Alice')
    const firstRepo = createRepository(first, 'first')
    createRepository(first, 'second')
    const second = createWorkspaceStore({ local: storage.local, session: new MemoryStorage() })
    second.login('Alice')
    const before = storage.local.getItem(profileKey('alice'))
    first.selectRepository(firstRepo.id)
    expect(storage.local.getItem(profileKey('alice'))).toBe(before)
    second.toggleSaved('still-saveable')
    expect(second.snapshot().storageError).toBe('')
    expect(createWorkspaceStore(storage).snapshot().activeRepositoryId).toBe(firstRepo.id)
  })

  it('rejects failed comment and status persistence without false success or clearing existing state', async () => {
    const storage = makeStorage()
    const first = createWorkspaceStore(storage)
    first.login('Alice')
    const repo = createRepository(first)
    const workspace = useWorkspace({ local: storage.local, session: new MemoryStorage() })
    await workspace.login('Alice')
    first.toggleSaved('concurrent')
    const comment = await workspace.addComment('demo-001', 'Keep this draft')
    expect(comment).toMatchObject({ ok: false, kind: 'conflict' })
    expect(workspace.comments.value).toEqual([])
    const review = await workspace.setReviewStatus(repo.id, 'demo-001', 'resolved')
    expect(review.ok).toBe(false)
    expect(workspace.getReviewStatus(repo.id, 'demo-001')).toBe('unreviewed')
    await workspace.reloadLatest()
    expect((await workspace.addComment('demo-001', 'Retry kept draft')).ok).toBe(true)
  })

  it('isolates one corrupt row, exports its original, blocks overwrite and resumes only after a backup', () => {
    const storage = makeStorage()
    const first = createWorkspaceStore(storage)
    first.login('Alice')
    first.toggleSaved('good')
    first.addComment('demo-001', 'Valid comment')
    const stored = JSON.parse(storage.local.getItem(profileKey('alice'))!)
    stored.data.comments.push({ id: 'bad', articleId: 'demo-001', body: '\u202e', authorId: stored.user.id })
    const original = JSON.stringify(stored)
    storage.local.setItem(profileKey('alice'), original)
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot().user?.displayName).toBe('Alice')
    expect(restored.snapshot().savedIds).toEqual(['good'])
    expect(restored.snapshot().comments).toHaveLength(1)
    expect(restored.snapshot().recoveryAvailable).toBe(true)
    expect(() => restored.toggleSaved('before-consent')).toThrow('エクスポート')
    expect(storage.local.getItem(profileKey('alice'))).toBe(original)
    expect(JSON.parse(restored.exportRecovery()).originals[0].raw).toBe(original)
    restored.resetRecovery()
    expect(Array.from(storage.local.values.entries()).some(([key, value]) => key.includes(':recovery:') && value === original)).toBe(true)
    restored.toggleSaved('after-consent')
    expect(createWorkspaceStore(storage).snapshot().savedIds).toEqual(['good', 'after-consent'])
  })

  it.each(['{broken', JSON.stringify({ version: 99, data: { future: 'keep me' } })])('does not silently overwrite unreadable guest data: %s', raw => {
    const storage = makeStorage()
    storage.session.setItem(guestKey, raw)
    const store = createWorkspaceStore(storage)
    expect(() => store.addComment('demo-001', 'new')).toThrow()
    expect(storage.session.getItem(guestKey)).toBe(raw)
    expect(store.snapshot().comments).toEqual([])
    expect(JSON.parse(store.exportRecovery()).originals[0].raw).toBe(raw)
    store.resetRecovery()
    store.addComment('demo-001', 'new')
    expect(createWorkspaceStore(storage).snapshot().comments).toHaveLength(1)
  })

  it('keeps the original intact when the recovery backup cannot be saved', () => {
    const storage = makeStorage()
    storage.session.setItem(guestKey, '{broken')
    const session = { getItem: (key: string) => storage.session.getItem(key), removeItem: vi.fn(), setItem: () => { throw new Error('Quota') } }
    const store = createWorkspaceStore({ session, local: storage.local })
    expect(() => store.resetRecovery()).toThrow('退避できない')
    expect(storage.session.getItem(guestKey)).toBe('{broken')
    expect(session.removeItem).not.toHaveBeenCalled()
    expect(store.snapshot().recoveryAvailable).toBe(true)
  })

  it('rejects recovery if another tab changed the source after it was read', () => {
    const storage = makeStorage()
    storage.local.setItem(profileKey('alice'), '{broken')
    const store = createWorkspaceStore(storage)
    expect(() => store.login('Alice')).toThrow()
    storage.local.setItem(profileKey('alice'), '{changed')
    expect(() => store.resetRecovery()).toThrow()
    expect(storage.local.getItem(profileKey('alice'))).toBe('{changed')
  })

  it('restores only known fields and keeps actual comments across the rewrite', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.addComment('demo-001', 'safe')
    const raw = JSON.parse(storage.session.getItem(guestKey)!)
    raw.data.extra = 'not trusted'
    raw.data.comments[0].extra = 'not trusted'
    storage.session.setItem(guestKey, JSON.stringify(raw))
    const restored = createWorkspaceStore(storage)
    restored.toggleSaved('demo-001')
    const persisted = JSON.parse(storage.session.getItem(guestKey)!)
    expect(persisted.data.extra).toBeUndefined()
    expect(persisted.data.comments[0].extra).toBeUndefined()
    expect(persisted.data.comments[0].body).toBe('safe')
  })

  it('retains an unsaved submitted article while comments or review statuses refer to it', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    const reference = { input: 'CVE-2026-12345', createdAt: '2026-09-25T03:00:00.000Z' }
    const item = createSubmittedReport(reference.input, 'cve', reference.createdAt)
    const repo = createRepository(store)
    store.addComment(item.id, 'keep reference', reference)
    store.setReviewStatus(repo.id, item.id, 'investigating', reference)
    store.toggleSaved(item.id, reference)
    store.toggleSaved(item.id)
    const restored = createWorkspaceStore(storage)
    expect(restored.snapshot().savedIds).toEqual([])
    expect(getSavedReportItems(restored.snapshot().savedReportReferences)[0]?.id).toBe(item.id)
    restored.deleteComment(restored.snapshot().comments[0]!.id)
    expect(restored.snapshot().savedReportReferences[item.id]).toBeDefined()
    restored.setReviewStatus(repo.id, item.id, 'unreviewed')
    expect(restored.snapshot().savedReportReferences[item.id]).toBeUndefined()
  })

  it('rejects submitted article activity without a recoverable reference', () => {
    const store = createWorkspaceStore(makeStorage())
    expect(() => store.addComment('submitted-CVE-2026-12345', 'orphan')).toThrow('参照情報')
    expect(store.snapshot().comments).toEqual([])
  })

  it('handles a failed guest-clear stage without confirming a partial login', () => {
    const storage = makeStorage()
    const session = {
      getItem: (key: string) => storage.session.getItem(key),
      setItem: (key: string, raw: string) => {
        if (key === guestKey && JSON.parse(raw).data.comments.length === 0) throw new Error('blocked guest clear')
        storage.session.setItem(key, raw)
      }, removeItem: (key: string) => storage.session.removeItem(key),
    }
    const store = createWorkspaceStore({ session, local: storage.local })
    store.addComment('demo-001', 'guest draft')
    expect(() => store.login('Alice')).toThrow('移行できなかった')
    expect(store.snapshot().user).toBeNull()
    expect(store.snapshot().comments[0]?.body).toBe('guest draft')
    expect(storage.session.getItem(activeKey)).toBeNull()
    expect(storage.local.getItem(profileKey('alice'))).toBeNull()
  })

  it('keeps a failed logout visibly logged in until the marker is removed', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore({ local: storage.local, session: {
      getItem: (key: string) => storage.session.getItem(key), setItem: (key: string, raw: string) => storage.session.setItem(key, raw),
      removeItem: () => { throw new Error('blocked logout') },
    } })
    store.login('Alice')
    expect(() => store.logout()).toThrow('ログイン状態')
    expect(store.snapshot().user?.displayName).toBe('Alice')
    expect(createWorkspaceStore(storage).snapshot().user?.displayName).toBe('Alice')
  })

  it.each(['\u0085', '\u202e', '\u2066', '\u200b', '\ufeff'])('rejects misleading invisible controls: %s', char => {
    const store = createWorkspaceStore(makeStorage())
    expect(() => store.login(`alice${char}`)).toThrow('制御文字')
    expect(() => store.addComment('demo-001', `comment${char}`)).toThrow('制御文字')
  })

  it('counts Unicode code points consistently and validates real ISO timestamps', () => {
    const storage = makeStorage()
    const store = createWorkspaceStore(storage)
    store.login('😀'.repeat(40))
    expect(() => store.login('😀'.repeat(41))).toThrow('40')
    store.addComment('demo-001', '😀'.repeat(2000))
    expect(createWorkspaceStore(storage).snapshot().comments).toHaveLength(1)
    const key = Array.from(storage.local.values.keys())[0]!
    const raw = JSON.parse(storage.local.getItem(key)!)
    raw.data.comments[0].createdAt = '2026-02-30T00:00:00.000Z'
    storage.local.setItem(key, JSON.stringify(raw))
    expect(createWorkspaceStore(storage).snapshot().comments).toEqual([])
  })

  it('uses secure random bytes when randomUUID is absent in a LAN browser context', () => {
    const random = crypto.getRandomValues.bind(crypto)
    vi.stubGlobal('crypto', { getRandomValues: random })
    const ids = Array.from({ length: 64 }, () => localId())
    expect(new Set(ids).size).toBe(64)
    expect(ids.every(id => /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(id))).toBe(true)
    const store = createWorkspaceStore(makeStorage())
    createRepository(store)
    store.login('Alice')
    store.addComment('demo-001', 'works on HTTP LAN')
    expect(store.snapshot().comments).toHaveLength(1)
  })

  it('exposes pending state and prevents duplicate actions until an adapter resolves', async () => {
    const store = createWorkspaceStore(makeStorage())
    let release!: () => void
    const ready = new Promise<void>(resolve => { release = resolve })
    const workspace = useWorkspace(undefined, { ...store, addComment: async (...args) => { await ready; store.addComment(...args) } })
    const pending = workspace.addComment('demo-001', 'once')
    expect(workspace.pending.value).toBe(true)
    expect(workspace.pendingAction.value).toBe('addComment')
    expect(await workspace.addComment('demo-001', 'twice')).toMatchObject({ ok: false, kind: 'busy' })
    release()
    expect((await pending).ok).toBe(true)
    expect(workspace.pending.value).toBe(false)
    expect(workspace.comments.value.map(item => item.body)).toEqual(['once'])
  })

  it('notifies live profiles about external saves and removes the listener on disposal', async () => {
    const windowEvents = new EventTarget()
    const remove = vi.spyOn(windowEvents, 'removeEventListener')
    vi.stubGlobal('window', windowEvents)
    const scope = effectScope()
    const workspace = scope.run(() => useWorkspace(makeStorage()))!
    await workspace.login('Alice')
    const event = new Event('storage')
    Object.defineProperty(event, 'key', { value: profileKey('alice') })
    windowEvents.dispatchEvent(event)
    expect(workspace.conflict.value).toBe(true)
    expect(workspace.storageError.value).toContain('別のタブ')
    scope.stop()
    expect(remove).toHaveBeenCalledWith('storage', expect.any(Function))
  })
})


it('enforces repository, comment and saved-article limits while permitting removal at the limit', () => {
  const storage = makeStorage()
  const repositories = Array.from({ length: 20 }, (_, n) => ({ id: `repo:${n}`, url: `https://github.com/example/repo-${n}`, label: `example/repo-${n}` }))
  const comments = Array.from({ length: 500 }, (_, n) => ({ id: `comment:${n}`, articleId: 'demo-001', authorId: 'guest', authorName: 'ゲスト', body: 'kept', createdAt: '2026-09-25T00:00:00.000Z' }))
  const data = { repositories, comments, activeRepositoryId: 'repo:0', savedIds: Array.from({ length: 5000 }, (_, n) => `article-${n}`), savedReportReferences: {}, reviewStatuses: {} }
  storage.session.setItem(guestKey, JSON.stringify({ version: 1, data }))
  const store = createWorkspaceStore(storage)
  expect(store.addRepository('https://github.com/example/overflow')).toMatchObject({ ok: false })
  expect(() => store.addComment('demo-001', 'overflow')).toThrow('500件')
  expect(() => store.toggleSaved('overflow')).toThrow('5000件')
  store.removeRepository('repo:0')
  store.deleteComment('comment:0')
  store.toggleSaved('article-0')
  expect(store.addRepository('https://github.com/example/replacement').ok).toBe(true)
  store.addComment('demo-001', 'replacement')
  store.toggleSaved('replacement')
  const restored = createWorkspaceStore(storage).snapshot()
  expect(restored.repositories).toHaveLength(20)
  expect(restored.comments).toHaveLength(500)
  expect(restored.savedIds).toHaveLength(5000)
})

it('returns a generic safe error for an unexpected server-adapter exception', async () => {
  const store = createWorkspaceStore(makeStorage())
  const workspace = useWorkspace(undefined, { ...store, login: async () => { throw new Error('secret db connection string') } })
  const result = await workspace.login('Alice')
  expect(result).toMatchObject({ ok: false, message: '処理を完了できませんでした。もう一度お試しください。' })
  expect(workspace.pending.value).toBe(false)
})


it('protects unreadable guest storage from both mutations and profile transfer until a successful reread', () => {
  const storage = makeStorage()
  const first = createWorkspaceStore(storage)
  first.toggleSaved('original')
  let failRead = true
  const session = { getItem: (key: string) => {
    if (key === guestKey && failRead) throw new Error('Read blocked')
    return storage.session.getItem(key)
  }, setItem: (key: string, raw: string) => storage.session.setItem(key, raw), removeItem: (key: string) => storage.session.removeItem(key) }
  const original = storage.session.getItem(guestKey)
  const store = createWorkspaceStore({ session, local: storage.local })
  expect(() => store.toggleSaved('new')).toThrow('上書きしていません')
  expect(() => store.login('Alice')).toThrow('ゲストの保存データ')
  expect(storage.session.getItem(guestKey)).toBe(original)
  expect(storage.local.getItem(profileKey('alice'))).toBeNull()
  failRead = false
  store.reloadLatest()
  expect(store.snapshot().savedIds).toEqual(['original'])
  store.toggleSaved('new')
  expect(store.snapshot().savedIds).toEqual(['original', 'new'])
})

it('does not erase quarantined guest originals during profile creation', () => {
  const storage = makeStorage()
  storage.session.setItem(guestKey, '{broken')
  const store = createWorkspaceStore(storage)
  expect(() => store.login('Alice')).toThrow('ゲストの保存データ')
  expect(storage.session.getItem(guestKey)).toBe('{broken')
  expect(storage.local.values.size).toBe(0)
})


it('clears quarantine when a corrected record is reloaded without overwriting it', () => {
  const storage = makeStorage()
  const first = createWorkspaceStore(storage)
  first.toggleSaved('original')
  const valid = storage.session.getItem(guestKey)!
  storage.session.setItem(guestKey, '{broken')
  const restored = createWorkspaceStore(storage)
  expect(restored.snapshot().recoveryAvailable).toBe(true)
  storage.session.setItem(guestKey, valid)
  restored.reloadLatest()
  expect(restored.snapshot().recoveryAvailable).toBe(false)
  expect(restored.snapshot().storageError).toBe('')
  restored.toggleSaved('new')
  expect(restored.snapshot().savedIds).toEqual(['original', 'new'])
})


it('does not include another profile recovery export after logout or switching profiles', () => {
  const storage = makeStorage()
  const first = createWorkspaceStore(storage)
  first.login('Alice')
  first.addComment('demo-001', 'private-alice')
  const stored = JSON.parse(storage.local.getItem(profileKey('alice'))!)
  stored.data.savedIds.push('invalid id')
  storage.local.setItem(profileKey('alice'), JSON.stringify(stored))
  const restored = createWorkspaceStore(storage)
  expect(restored.snapshot().recoveryAvailable).toBe(true)
  restored.logout()
  expect(restored.exportRecovery()).not.toContain('private-alice')
  restored.login('Bob')
  expect(restored.exportRecovery()).not.toContain('private-alice')
  expect(restored.snapshot().recoveryAvailable).toBe(false)
})


it('quarantines legacy orphan comments while preserving submitted comments with valid references', () => {
  const storage = makeStorage()
  const store = createWorkspaceStore(storage)
  const reference = { input: 'CVE-2026-12345', createdAt: '2026-09-25T03:00:00.000Z' }
  const article = createSubmittedReport(reference.input, 'cve', reference.createdAt)
  store.addComment(article.id, 'valid', reference)
  const raw = JSON.parse(storage.session.getItem(guestKey)!)
  raw.data.comments.push({ ...raw.data.comments[0], id: 'comment:orphan', articleId: 'submitted-CVE-2026-99999', body: 'legacy orphan' })
  const original = JSON.stringify(raw)
  storage.session.setItem(guestKey, original)
  const restored = createWorkspaceStore(storage)
  expect(restored.snapshot().comments.map(comment => comment.body)).toEqual(['valid'])
  expect(restored.snapshot().recoveryAvailable).toBe(true)
  expect(JSON.parse(restored.exportRecovery()).originals[0].raw).toBe(original)
  restored.resetRecovery()
  expect(createWorkspaceStore(storage).snapshot().comments).toHaveLength(1)
})
