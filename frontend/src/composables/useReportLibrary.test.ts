import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { effectScope, nextTick, ref, toRaw } from 'vue'
import { getSavedReportItems, historicalReports } from '../services/reports'
import { useReportLibrary } from './useReportLibrary'

const storageKey = 'vulns-news-report-lab-v2:guest'
const ownerStorageKey = (id: string) => `vulns-news-report-lab-v2:user:${encodeURIComponent(id)}`
const scopes: ReturnType<typeof effectScope>[] = []
let stored: Map<string, string>

function mountLibrary(owner?: Parameters<typeof useReportLibrary>[0]) {
  const scope = effectScope()
  scopes.push(scope)
  const library = scope.run(() => useReportLibrary(owner))!
  return { library, stop: () => scope.stop() }
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime('2026-09-25T03:00:00.000Z')
  stored = new Map()
  vi.stubGlobal('sessionStorage', {
    getItem: (key: string) => stored.get(key) ?? null,
    setItem: (key: string, value: string) => stored.set(key, value),
    removeItem: (key: string) => stored.delete(key),
    clear: () => stored.clear(),
  })
  vi.stubGlobal('document', { visibilityState: 'visible' })
})

afterEach(() => {
  for (const scope of scopes.splice(0)) scope.stop()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('report library interaction scenarios', () => {
  it('normalizes repeated CVE input and keeps one active request', () => {
    const { library } = mountLibrary()

    library.submit(' cve-2026-12345 ')
    library.submit('CVE-2026-12345')

    expect(library.jobs.value).toHaveLength(1)
    expect(library.catalog.value.filter(item => item.advisoryId === 'CVE-2026-12345')).toHaveLength(1)
    expect(library.jobs.value[0]?.status).toBe('queued')
  })

  it('deduplicates a CVE and its recognized advisory URL while analysis is pending', () => {
    const { library } = mountLibrary()

    library.submit('CVE-2026-12345')
    library.submit('https://nvd.nist.gov/vuln/detail/CVE-2026-12345')

    expect(library.jobs.value).toHaveLength(1)
    expect(library.jobs.value[0]?.newCount).toBe(1)
  })

  it('reuses an existing historical report immediately without silently renewing tracking', () => {
    const { library } = mountLibrary()
    const existing = historicalReports[0]!
    const before = structuredClone(toRaw(library.lifecycles.value[existing.id]!))

    library.submit(existing.sources[0]!.url)

    expect(library.jobs.value[0]).toMatchObject({
      status: 'completed',
      reusedCount: 1,
      newCount: 0,
      reportIds: [existing.id],
    })
    expect(library.lifecycles.value[existing.id]).toEqual(before)
  })

  it('shows reusable historical results during a repository scan, then adds the new report', async () => {
    const { library } = mountLibrary()
    const repository = 'https://github.com/example/frontend'

    const knownIds = library.knownRepositoryItems(repository).map(item => item.id)
    const reusableIds = [...knownIds, 'history-001']
    library.scanRepository(repository)
    expect(library.scanFor(repository)).toMatchObject({ reusedCount: reusableIds.length, newCount: 1, status: 'queued' })
    expect(library.repositoryItems(repository).map(item => item.id)).toEqual(reusableIds)

    await vi.advanceTimersByTimeAsync(6500)

    expect(library.scanFor(repository)?.status).toBe('completed')
    const results = library.repositoryItems(repository)
    expect(results.map(item => item.id)).toEqual([...reusableIds, 'history-002'])
    expect(library.lifecycles.value['history-001']?.revision).toBe(1)
    expect(library.lifecycles.value['history-002']?.revision).toBe(1)
    expect(results.find(item => item.id === 'history-002')?.repositoryAnalysis).toBe('pending')
  })

  it('deduplicates normalized repository URLs before queueing work', () => {
    const { library } = mountLibrary()

    library.scanRepository('https://github.com/example/frontend')
    library.scanRepository('https://github.com/example/frontend.git/')

    expect(library.jobs.value).toHaveLength(1)
    expect(library.jobs.value[0]?.key).toBe('https://github.com/example/frontend')
  })

  it('does not automatically analyze an expired report and manual analysis does not renew its deadline', async () => {
    const { library } = mountLibrary()
    const reportId = 'history-001'
    const deadline = library.lifecycles.value[reportId]!.trackingUntil
    vi.setSystemTime('2026-09-26T03:00:00.000Z')

    await vi.advanceTimersByTimeAsync(1000)
    expect(library.lifecycles.value[reportId]?.revision).toBe(1)

    library.reanalyze(reportId)
    await vi.advanceTimersByTimeAsync(6500)

    expect(library.lifecycles.value[reportId]).toMatchObject({
      revision: 2,
      trackingUntil: deadline,
      nextCheckAt: null,
    })
    expect(library.lifecycles.value[reportId]?.history.at(-1)?.reason).toBe('manual')
  })

  it('renews tracking only on the separate renewal action without fabricating a new analysis', () => {
    const { library } = mountLibrary()
    const reportId = 'history-001'
    const analyzedAt = library.lifecycles.value[reportId]!.lastAnalyzedAt

    library.renew(reportId)

    expect(library.lifecycles.value[reportId]).toMatchObject({
      revision: 1,
      lastAnalyzedAt: analyzedAt,
      trackingUntil: '2026-10-02T03:00:00.000Z',
      nextCheckAt: '2026-09-26T03:00:00.000Z',
    })
  })

  it('reconstructs completed submitted reports and publication after a session reload', async () => {
    const first = mountLibrary()
    first.library.submit('CVE-2026-12345')
    await vi.advanceTimersByTimeAsync(6500)
    const reportId = first.library.jobs.value[0]!.reportIds[0]!
    first.library.publish()
    await nextTick()
    first.stop()

    const { library } = mountLibrary()

    expect(library.jobs.value[0]?.status).toBe('completed')
    expect(library.lifecycles.value[reportId]?.revision).toBe(1)
    expect(library.reports.value.some(report => report.item.id === reportId)).toBe(true)
    expect(library.additions('').map(item => item.id)).toContain(reportId)
    expect(library.publicationQueue.value).not.toContain(reportId)
  })

  it('preserves completed scheduled revisions across a session reload', async () => {
    const first = mountLibrary()
    await vi.advanceTimersByTimeAsync(1000)
    const lifecycle = first.library.lifecycles.value['demo-001']!
    expect(lifecycle.revision).toBeGreaterThan(1)
    const expected = { revision: lifecycle.revision, lastAnalyzedAt: lifecycle.lastAnalyzedAt, trackingUntil: lifecycle.trackingUntil }
    await nextTick()
    first.stop()

    const { library } = mountLibrary()

    expect(library.lifecycles.value['demo-001']).toMatchObject(expected)
  })

  it('keeps cancelled requests cancelled after time elapses and after a reload', async () => {
    const first = mountLibrary()
    first.library.submit('CVE-2026-12345')
    const job = first.library.jobs.value[0]!
    first.library.cancel(job.id)
    await vi.advanceTimersByTimeAsync(10000)
    await nextTick()
    expect(job.status).toBe('cancelled')
    expect(first.library.publicationQueue.value).toEqual([])
    first.stop()

    const { library } = mountLibrary()
    expect(library.jobs.value[0]?.status).toBe('cancelled')
    expect(library.lifecycles.value[job.reportIds[0]!]?.revision).toBe(0)
  })

  it('keeps the next scheduled check after renewal, update and reload without creating an extra revision', async () => {
    const first = mountLibrary()
    const reportId = 'history-001'
    first.library.renew(reportId)
    vi.setSystemTime('2026-09-26T03:00:00.000Z')
    await vi.advanceTimersByTimeAsync(1000)
    const lifecycle = first.library.lifecycles.value[reportId]!
    const expected = { ...lifecycle, history: lifecycle.history.map(entry => ({ ...entry })) }
    expect(expected.revision).toBe(2)
    expect(expected.nextCheckAt).toBe('2026-09-27T03:00:01.000Z')
    await nextTick()
    first.stop()

    const { library } = mountLibrary()

    expect(library.lifecycles.value[reportId]).toEqual(expected)
    await vi.advanceTimersByTimeAsync(1000)
    expect(library.lifecycles.value[reportId]).toEqual(expected)
  })

  it('still reuses existing reports when all five analysis slots are occupied', () => {
    const { library } = mountLibrary()
    for (let index = 0; index < 5; index += 1) library.submit('CVE-2026-' + (12340 + index))

    library.submit(historicalReports[0]!.sources[0]!.url)

    expect(library.submissionError.value).toBe('')
    expect(library.jobs.value).toHaveLength(6)
    expect(library.jobs.value[0]).toMatchObject({ status: 'completed', reusedCount: 1, newCount: 0 })
  })

  it('releases its interval on scope disposal', () => {
    const { stop } = mountLibrary()
    expect(vi.getTimerCount()).toBe(1)

    stop()

    expect(vi.getTimerCount()).toBe(0)
  })

  it('recovers from malformed session state with a usable fresh request form', () => {
    stored.set(storageKey, '{not json')
    const { library } = mountLibrary()

    expect(library.storageError.value).not.toBe('')
    library.submit('CVE-2026-12345')

    expect(library.jobs.value).toHaveLength(1)
  })
})

describe('report state validation and queue limits', () => {
  it('rejects a sixth request without adding an orphan report or lifecycle', () => {
    const { library } = mountLibrary()
    for (let index = 0; index < 5; index += 1) library.submit('CVE-2026-' + (12340 + index))
    const reportIds = library.catalog.value.map(item => item.id)
    const lifecycleIds = Object.keys(library.lifecycles.value)

    library.submit('CVE-2026-99999')

    expect(library.jobs.value).toHaveLength(5)
    expect(library.submissionError.value).toContain('5件')
    expect(library.catalog.value.map(item => item.id)).toEqual(reportIds)
    expect(Object.keys(library.lifecycles.value)).toEqual(lifecycleIds)
  })

  it('does not expose repository results when the scan was rejected for capacity', () => {
    const { library } = mountLibrary()
    for (let index = 0; index < 5; index += 1) library.submit('CVE-2026-' + (12340 + index))

    library.scanRepository('https://github.com/example/frontend')

    expect(library.scanFor('https://github.com/example/frontend')).toBeUndefined()
    expect(library.repositoryItems('https://github.com/example/frontend')).toEqual([])
  })

  it('enforces the active-job limit when retrying and allows retry after a slot is released', () => {
    const { library } = mountLibrary()
    library.submit('CVE-2026-90000')
    const failed = library.jobs.value[0]!
    failed.status = 'failed'
    for (let index = 0; index < 5; index += 1) library.submit('CVE-2026-' + (12340 + index))

    library.retry(failed.id)
    expect(failed.status).toBe('failed')
    expect(library.submissionError.value).toContain('5件')
    library.cancel(library.jobs.value[0]!.id)
    library.retry(failed.id)
    expect(failed.status).toBe('queued')
    expect(library.submissionError.value).toBe('')
  })

  it('does not retry a failed job while a newer request for the same report is active', () => {
    const { library } = mountLibrary()
    library.submit('CVE-2026-12345')
    const failed = library.jobs.value[0]!
    failed.status = 'failed'
    library.submit('CVE-2026-12345')

    library.retry(failed.id)

    expect(failed.status).toBe('failed')
    expect(library.jobs.value.filter(job => job.status === 'queued')).toHaveLength(1)
  })

  it('ignores malformed job records without coercing objects or dropping valid requests', () => {
    const request = { kind: 'submission', key: 'CVE-2026-12345', status: 'queued', createdAt: new Date().toISOString() }
    stored.set(storageKey, JSON.stringify({ jobs: [
      { ...request, kind: { toString: null } },
      { ...request, status: 'approved' },
      { ...request, createdAt: '+275760-09-13T00:00:00.000Z' },
      { ...request, createdAt: '2027-01-01T00:00:00.000Z' },
      request,
    ] }))

    const { library } = mountLibrary()

    expect(library.jobs.value).toHaveLength(1)
    expect(library.jobs.value[0]?.status).toBe('queued')
    expect(library.storageError.value).toBe('')
  })

  it('deduplicates and bounds restored active requests before creating report records', () => {
    const request = { kind: 'submission', status: 'queued', createdAt: new Date().toISOString() }
    const jobs = Array.from({ length: 6 }, (_, index) => ({ ...request, key: 'CVE-2026-' + (12340 + index) }))
    stored.set(storageKey, JSON.stringify({ jobs: [...jobs, jobs[0]] }))

    const { library } = mountLibrary()

    expect(library.jobs.value).toHaveLength(5)
    expect(new Set(library.jobs.value.map(job => job.key)).size).toBe(5)
    expect(library.catalog.value.filter(item => item.id.startsWith('submitted-'))).toHaveLength(5)
  })

  it('rejects prototype keys and inconsistent revision histories from stored lifecycles', () => {
    const initial = mountLibrary()
    const base = structuredClone(toRaw(initial.library.lifecycles.value['demo-001']!))
    initial.stop()
    stored.set(storageKey, JSON.stringify({ lifecycles: Object.fromEntries([
      ['__proto__', { ...base, articleId: '__proto__' }],
      ['constructor', { ...base, articleId: 'constructor' }],
      ['demo-001', { ...base, revision: 999 }],
    ]) }))

    const { library } = mountLibrary()

    expect(library.lifecycles.value['demo-001']).toEqual(base)
    expect(Object.hasOwn(library.lifecycles.value, '__proto__')).toBe(false)
    expect(Object.hasOwn(library.lifecycles.value, 'constructor')).toBe(false)
    expect(Object.getPrototypeOf(toRaw(library.lifecycles.value))).toBe(Object.prototype)
  })

  it('does not publish a cancelled request through forged stored publication or lifecycle fields', async () => {
    const first = mountLibrary()
    first.library.submit('CVE-2026-12345')
    const job = first.library.jobs.value[0]!
    const id = job.reportIds[0]!
    first.library.cancel(job.id)
    await nextTick()
    first.stop()
    const state = JSON.parse(stored.get(storageKey)!)
    state.publishedIds = [id]
    state.lifecycles[id] = { ...state.lifecycles[id], revision: 1, lastAnalyzedAt: new Date().toISOString(), history: [{ revision: 1, analyzedAt: new Date().toISOString(), reason: 'manual' }] }
    stored.set(storageKey, JSON.stringify(state))

    const { library } = mountLibrary()

    expect(library.jobs.value[0]?.status).toBe('cancelled')
    expect(library.lifecycles.value[id]?.revision).toBe(0)
    expect(library.additions('')).toEqual([])
  })

  it('reports oversized storage and still accepts a fresh request', () => {
    stored.set(storageKey, ' '.repeat(200_000))
    const { library } = mountLibrary()

    expect(library.storageError.value).not.toBe('')
    library.submit('CVE-2026-12345')
    expect(library.jobs.value).toHaveLength(1)
  })

  it('resolves repository scan and result lookups with normalized URLs', () => {
    const { library } = mountLibrary()
    library.scanRepository('https://github.com/example/frontend.git/')

    expect(library.scanFor('https://github.com/example/frontend/')).toBeDefined()
    expect(library.repositoryItems('https://github.com/example/frontend.git/').length).toBeGreaterThan(0)
  })
  it('does not turn an unfinished cancelled request into a report through tracking renewal', async () => {
    const { library } = mountLibrary()
    library.submit('CVE-2026-12345')
    const job = library.jobs.value[0]!
    const reportId = job.reportIds[0]!
    library.cancel(job.id)
    library.renew(reportId)
    vi.setSystemTime('2026-09-26T03:00:00.000Z')

    await vi.advanceTimersByTimeAsync(1000)

    expect(job.status).toBe('cancelled')
    expect(library.lifecycles.value[reportId]?.revision).toBe(0)
    expect(library.reports.value.some(report => report.item.id === reportId)).toBe(false)
  })

})

it('keeps a published periodic report timestamp stable across a later reload', async () => {
  const first = mountLibrary()
  await vi.advanceTimersByTimeAsync(30_000)
  first.library.publish()
  const published = first.library.additions('').find(item => item.id === 'demo-013')!
  const timestamps = { publishedAt: published.publishedAt, updatedAt: published.updatedAt }
  await nextTick()
  first.stop()
  vi.setSystemTime('2026-09-27T03:00:00.000Z')

  const second = mountLibrary()

  expect(second.library.additions('').find(item => item.id === 'demo-013')).toMatchObject(timestamps)
})


it('keeps a restorable original submission reference when a later request uses an alias', async () => {
  const { library } = mountLibrary()
  library.submit('https://nvd.nist.gov/vuln/detail/CVE-2026-12345')
  const id = library.jobs.value[0]!.reportIds[0]!
  await vi.advanceTimersByTimeAsync(6500)
  library.submit('CVE-2026-12345')
  const reference = library.referenceFor(id)!
  expect(reference).toEqual({ input: 'https://nvd.nist.gov/vuln/detail/CVE-2026-12345', createdAt: '2026-09-25T03:00:00.000Z' })
  expect(getSavedReportItems({ [id]: reference })[0]?.id).toBe(id)
  expect(library.referenceFor('demo-001')).toBeUndefined()
})


describe('report library profile boundaries', () => {
  it('switches guest, Alice and Bob requests synchronously and restores each owner separately', async () => {
    const owner = ref<string | null>(null)
    const first = mountLibrary(owner)
    const library = first.library
    library.submit('CVE-2026-10001')
    const guestId = library.jobs.value[0]!.reportIds[0]!
    owner.value = 'user:alice'
    expect(library.jobs.value).toEqual([])
    expect(library.referenceFor(guestId)).toBeUndefined()
    expect(library.catalog.value.some(item => item.id === guestId)).toBe(false)

    library.submit('CVE-2026-10002')
    const aliceId = library.jobs.value[0]!.reportIds[0]!
    library.submit('invalid')
    expect(library.submissionError.value).not.toBe('')
    owner.value = 'user:bob'
    expect(library.jobs.value).toEqual([])
    expect(library.submissionError.value).toBe('')
    expect(library.referenceFor(aliceId)).toBeUndefined()
    expect(library.catalog.value.some(item => item.id === aliceId)).toBe(false)
    expect(Object.hasOwn(library.lifecycles.value, aliceId)).toBe(false)
    library.submit('CVE-2026-10003')

    owner.value = null
    expect(library.jobs.value.map(job => job.key)).toEqual(['CVE-2026-10001'])
    expect(library.referenceFor(guestId)?.input).toBe('CVE-2026-10001')
    owner.value = 'user:alice'
    expect(library.jobs.value.map(job => job.key)).toEqual(['CVE-2026-10002'])
    expect(library.referenceFor(aliceId)?.input).toBe('CVE-2026-10002')
    await nextTick()
    first.stop()

    const restored = mountLibrary(() => 'user:bob').library
    expect(restored.jobs.value.map(job => job.key)).toEqual(['CVE-2026-10003'])
    expect(restored.referenceFor(aliceId)).toBeUndefined()
    expect(restored.catalog.value.some(item => item.id === guestId)).toBe(false)
  })

  it('isolates repository results, tracking renewals and published or queued reports', async () => {
    const owner = ref<string | null>('user:alice')
    const { library } = mountLibrary(owner)
    const repository = 'https://github.com/example/frontend'
    const originalDeadline = library.lifecycles.value['history-001']!.trackingUntil
    library.scanRepository(repository)
    library.renew('history-001')
    library.submit('CVE-2026-10002')
    const aliceId = library.jobs.value[0]!.reportIds[0]!
    await vi.advanceTimersByTimeAsync(6500)
    library.publish()
    await vi.advanceTimersByTimeAsync(24_000)
    expect(library.publicationQueue.value).toContain('demo-013')

    owner.value = 'user:bob'
    expect(library.repositoryItems(repository)).toEqual([])
    expect(library.scanFor(repository)).toBeUndefined()
    expect(library.lifecycles.value['history-001']!.trackingUntil).toBe(originalDeadline)
    expect(library.additions('')).toEqual([])
    expect(library.publicationQueue.value).toEqual([])
    expect(library.reports.value.some(report => report.item.id === aliceId)).toBe(false)

    owner.value = 'user:alice'
    expect(library.scanFor(repository)?.status).toBe('completed')
    expect(library.repositoryItems(repository).length).toBeGreaterThan(0)
    expect(library.lifecycles.value['history-001']!.trackingUntil).not.toBe(originalDeadline)
    expect(library.additions('').map(item => item.id)).toContain(aliceId)
    expect(library.publicationQueue.value).toEqual(['demo-013'])
  })

  it('does not write queued old-owner changes or finish old-owner jobs in a new scope', async () => {
    const owner = ref<string | null>('user:alice')
    const { library } = mountLibrary(owner)
    library.submit('CVE-2026-10002')
    const aliceId = library.jobs.value[0]!.reportIds[0]!
    // Switch before the deep persistence watcher gets its next tick.
    owner.value = 'user:bob'
    library.submit('CVE-2026-10003')
    await vi.advanceTimersByTimeAsync(6500)

    expect(library.jobs.value.map(job => job.key)).toEqual(['CVE-2026-10003'])
    expect(library.publicationQueue.value).not.toContain(aliceId)
    expect(library.referenceFor(aliceId)).toBeUndefined()
    expect(JSON.parse(stored.get(ownerStorageKey('user:alice'))!).jobs.map((job: { key: string }) => job.key)).toEqual(['CVE-2026-10002'])
    expect(stored.get(ownerStorageKey('user:bob'))).not.toContain('CVE-2026-10002')
    expect(vi.getTimerCount()).toBe(1)
  })

  it('keeps in-memory work per owner when session persistence fails', async () => {
    vi.spyOn(sessionStorage, 'setItem').mockImplementation(() => { throw new Error('storage blocked') })
    const owner = ref<string | null>('user:alice')
    const { library } = mountLibrary(owner)
    library.submit('CVE-2026-10002')
    await nextTick()
    expect(library.storageError.value).not.toBe('')

    owner.value = 'user:bob'
    expect(library.storageError.value).toBe('')
    expect(library.jobs.value).toEqual([])
    library.submit('CVE-2026-10003')
    owner.value = 'user:alice'
    expect(library.jobs.value.map(job => job.key)).toEqual(['CVE-2026-10002'])
  })

  it('never assigns legacy unowned requests to the guest or an arbitrary profile', () => {
    const legacyKey = 'vulns-news-report-lab-v1'
    const raw = JSON.stringify({ jobs: [{ kind: 'submission', key: 'CVE-2026-19999', status: 'completed', createdAt: new Date().toISOString() }] })
    stored.set(legacyKey, raw)
    const owner = ref<string | null>(null)
    const { library } = mountLibrary(owner)
    expect(library.jobs.value).toEqual([])
    owner.value = 'user:alice'
    expect(library.jobs.value).toEqual([])
    expect(library.catalog.value.some(item => item.advisoryId === 'CVE-2026-19999')).toBe(false)
    expect(stored.get(legacyKey)).toBe(raw)
  })

  it("does not display another owner's malformed-session error", () => {
    stored.set(ownerStorageKey('user:alice'), '{invalid')
    const owner = ref<string | null>('user:alice')
    const { library } = mountLibrary(owner)
    expect(library.storageError.value).not.toBe('')
    owner.value = 'user:bob'
    expect(library.storageError.value).toBe('')
    expect(library.jobs.value).toEqual([])
  })
})
