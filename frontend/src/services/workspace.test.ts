import { describe, expect, it } from 'vitest'
import { reactive } from 'vue'
import { useWorkspace } from '../composables/useWorkspace'
import { createWorkspaceStore, type WorkspaceStorage } from './workspace'
import { createSubmittedReport, getSavedReportItems } from './reports'
import type { ReviewStatus } from '../types/workspace'

class MemoryStorage {
  values = new Map<string, string>()
  getItem(key: string) { return this.values.get(key) ?? null }
  setItem(key: string, value: string) { this.values.set(key, value) }
  removeItem(key: string) { this.values.delete(key) }
}
const makeStorage = () => ({ session: new MemoryStorage(), local: new MemoryStorage() })
const guestKey = 'vulns-news:workspace:guest:v1'
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
    expect(restored.snapshot().user).toBeNull()
    expect(restored.snapshot().comments).toEqual([])
    expect(restored.snapshot().storageError).toContain('形式')
  })

  it('continues in memory when storage is unavailable and preserves guest data on a failed migration', () => {
    const store = createWorkspaceStore({ session: null, local: null })
    store.toggleSaved('guest-only')
    store.login('Alice')
    store.toggleSaved('account-only')
    expect(store.snapshot().storageError).not.toBe('')
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
    store.login('Alice')
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

  it('updates composable refs immediately through the public methods', () => {
    const workspace = useWorkspace(makeStorage())
    const added = workspace.addRepository('https://github.com/example/frontend')
    if (!added.ok) throw new Error(added.message)
    workspace.toggleSaved('demo-001')
    workspace.addComment('demo-001', '確認中')
    workspace.setReviewStatus(added.repository.id, 'demo-001', 'investigating')
    expect(workspace.repositories.value).toHaveLength(1)
    expect(workspace.activeRepositoryId.value).toBe(added.repository.id)
    expect(workspace.savedIds.value).toEqual(['demo-001'])
    expect(workspace.comments.value).toHaveLength(1)
    expect(workspace.getReviewStatus(added.repository.id, 'demo-001')).toBe('investigating')
    workspace.login('Alice')
    expect(workspace.user.value?.displayName).toBe('Alice')
    workspace.logout()
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
    store.login('Alice')
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
    store.addComment('demo-001', '\\'.repeat(2000))
    expect(store.snapshot().comments).toHaveLength(count + 1)
    expect(store.snapshot().storageError).toContain('保存できません')
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

  second.toggleSaved('from-second-tab')

  expect(storage.local.getItem(profileKey('alice'))).toBe(newerSave)
  expect(second.snapshot().savedIds).toEqual(['original', 'from-second-tab'])
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
  expect(first.snapshot().storageError).toContain('別のタブ')
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

  it('transfers guest references into a new profile and exposes them through the composable', () => {
    const workspace = useWorkspace(makeStorage())
    workspace.toggleSaved(article.id, reference)
    workspace.login('Alice')
    expect(workspace.savedReportReferences.value[article.id]).toEqual(reference)
    workspace.logout()
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
    expect(restored.snapshot().savedIds).toEqual([])
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
