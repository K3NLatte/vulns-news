import { computed, effectScope, onScopeDispose, ref, shallowRef, toValue, watch, type MaybeRefOrGetter } from 'vue'
import { mockFeed, repositoryFeedFor } from '../mocks/feed'
import { parseRepositoryUrl } from '../services/feed'
import { createReportLifecycle, createSubmittedReport, findExistingReport, historicalReports, isTrackingActive, normalizeReportInput, renewReportTracking, updateReportLifecycle } from '../services/reports'
import type { FeedItem } from '../types/feed'
import type { InvestigationJob } from '../types/investigation'
import type { ReportLifecycle, SavedReportReference } from '../types/reports'
import { isRecord, isStoredDate, MAX_ACTIVE_REPORT_JOBS, MAX_REPORT_JOBS, MAX_REPORT_SESSION_LENGTH, parseStoredJobs, parseStoredLifecycle } from '../services/reportSession'

const storagePrefix = 'vulns-news-report-lab-v2'
const active = (job: InvestigationJob) => ['queued', 'collecting', 'analyzing'].includes(job.status)
// Local scenario timing, independent of backend progress or scheduling contracts.
const jobDuration = 6000

/** Each browser-local profile owns its requests, results and tracking state. */
export function useReportLibrary(owner: MaybeRefOrGetter<string | null | undefined> = null) {
  // Keep current-tab work available across profile switches even when storage fails.
  const sessions = new Map<string, string>()
  const keyForOwner = () => {
    const id = toValue(owner)
    return id == null ? `${storagePrefix}:guest` : `${storagePrefix}:user:${encodeURIComponent(id)}`
  }
  let scope = effectScope()
  const current = shallowRef(scope.run(() => createReportLibrary(keyForOwner(), sessions))!)
  watch(keyForOwner, key => {
    // Disposal saves pending changes for the old owner and stops its queued watchers
    // and timer before any new-owner state becomes available.
    scope.stop()
    scope = effectScope()
    current.value = scope.run(() => createReportLibrary(key, sessions))!
  }, { flush: 'sync' })
  onScopeDispose(() => scope.stop())

  return {
    now: computed(() => current.value.now.value),
    jobs: computed(() => current.value.jobs.value),
    catalog: computed(() => current.value.catalog.value),
    lifecycles: computed(() => current.value.lifecycles.value),
    reports: computed(() => current.value.reports.value),
    publicationQueue: computed(() => current.value.publicationQueue.value),
    submissionError: computed(() => current.value.submissionError.value),
    storageError: computed(() => current.value.storageError.value),
    referenceFor: (id: string) => current.value.referenceFor(id),
    submit: (input: string) => current.value.submit(input),
    reanalyze: (id: string) => current.value.reanalyze(id),
    renew: (id: string) => current.value.renew(id),
    retry: (id: string) => current.value.retry(id),
    cancel: (id: string) => current.value.cancel(id),
    publish: () => current.value.publish(),
    scanRepository: (url: string) => current.value.scanRepository(url),
    scanFor: (url: string) => current.value.scanFor(url),
    additions: (url: string) => current.value.additions(url),
    activeJobFor: (id: string) => current.value.activeJobFor(id),
    repositoryItems: (url: string) => current.value.repositoryItems(url),
    knownRepositoryItems: (url: string) => current.value.knownRepositoryItems(url),
  }
}

function createReportLibrary(storageKey: string, sessions: Map<string, string>) {
  const now = ref(new Date().toISOString())
  const jobs = ref<InvestigationJob[]>([])
  const created = ref<FeedItem[]>([])
  const lifecycles = ref<Record<string, ReportLifecycle>>({})
  const repositoryLinks = ref<Record<string, string[]>>({})
  const publishedIds = ref<string[]>([])
  const publicationQueue = ref<string[]>([])
  const renewals = ref<Record<string, string>>({})
  const submissionError = ref('')
  const storageError = ref('')
  const periodicReport: FeedItem = { ...structuredClone(mockFeed[0]!), id: 'demo-013', advisoryId: 'DEMO-2026-013', title: 'テンプレート評価の追加調査と修正版の検証', publishedAt: now.value, updatedAt: now.value }
  const catalog = computed(() => [...mockFeed, ...historicalReports, periodicReport, ...created.value])
  for (const item of catalog.value) lifecycles.value[item.id] = createReportLifecycle(item, now.value)
  const reports = computed(() => catalog.value.filter(item => (lifecycles.value[item.id]?.revision > 0 && item.id !== periodicReport.id) || publishedIds.value.includes(item.id)).map(item => ({ item, lifecycle: lifecycles.value[item.id]! })))

  function referenceFor(id: string): SavedReportReference | undefined {
    const item = created.value.find(item => item.id === id)
    if (!item) return undefined
    const job = jobs.value.find(job => {
      if (job.kind !== 'submission' || !job.reportIds.includes(id)) return false
      const parsed = normalizeReportInput(job.key)
      return parsed.ok && createSubmittedReport(parsed.key, parsed.kind, item.publishedAt).id === id
    })
    return job ? { input: job.key, createdAt: item.publishedAt } : undefined
  }

  function resolveSubmission(key: string, at: string) {
    const parsed = normalizeReportInput(key)
    if (!parsed.ok) return null
    const existing = findExistingReport(parsed.key, catalog.value)
    if (existing) return { item: existing, reused: lifecycles.value[existing.id]?.revision > 0 }
    const item = createSubmittedReport(parsed.key, parsed.kind, at)
    return { item, reused: false }
  }

  function prepareJob(kind: InvestigationJob['kind'], key: string, at: string): InvestigationJob | null {
    let reportIds: string[] = []
    let reusedCount = 0
    let label = key
    if (kind === 'submission') {
      const result = resolveSubmission(key, at)
      if (!result) return null
      reportIds = [result.item.id]
      reusedCount = result.reused ? 1 : 0
      label = result.item.advisoryId
    } else if (kind === 'repository') {
      const parsed = parseRepositoryUrl(key)
      if (!parsed.ok) return null
      label = parsed.label
      key = parsed.url
      reportIds = [...repositoryFeedFor(parsed.label).map(item => item.id), ...historicalReports.map(item => item.id)]
      reusedCount = reportIds.filter(id => lifecycles.value[id]?.revision > 0).length
    } else {
      const item = catalog.value.find(item => item.id === key)
      if (!item) return null
      reportIds = [item.id]
      label = item.advisoryId
    }
    return { id: crypto.randomUUID(), key, label, kind, status: kind === 'submission' && reusedCount ? 'completed' : 'queued', createdAt: at, reportIds, reusedCount, newCount: kind === 'reanalysis' ? 0 : reportIds.length - reusedCount }
  }

  function finish(job: InvestigationJob, at: string) {
    for (const id of job.reportIds) {
      const lifecycle = lifecycles.value[id]
      if (!lifecycle) continue
      if (job.kind === 'reanalysis' || lifecycle.revision === 0) {
        lifecycles.value[id] = updateReportLifecycle(lifecycle, at, 'manual')
      }
      if (job.kind === 'submission' && !publishedIds.value.includes(id) && !mockFeed.some(item => item.id === id) && !publicationQueue.value.includes(id)) publicationQueue.value.push(id)
    }
    if (job.kind === 'repository') repositoryLinks.value[job.key] = [...job.reportIds]
    job.status = 'completed'
  }

  function conflictingJob(job: InvestigationJob) {
    return jobs.value.find(current => active(current) && current.id !== job.id && (
      job.kind === 'repository' ? current.kind === job.kind && current.key === job.key
        : current.kind !== 'repository' && current.reportIds.some(id => job.reportIds.includes(id))
    ))
  }
  function hasCapacity(job: InvestigationJob) {
    if (job.status !== 'completed' && jobs.value.filter(active).length >= MAX_ACTIVE_REPORT_JOBS) {
      submissionError.value = '同時に依頼できるのは5件までです。完了後にもう一度お試しください。'
      return false
    }
    return true
  }
  function accept(job: InvestigationJob) {
    if (job.kind === 'submission') {
      const result = resolveSubmission(job.key, job.createdAt)
      if (result && !Object.hasOwn(lifecycles.value, result.item.id)) {
        created.value.push(result.item)
        lifecycles.value[result.item.id] = createReportLifecycle(result.item, job.createdAt, 'submitted')
      }
    }
    if (job.kind === 'repository') repositoryLinks.value[job.key] = job.reportIds.filter(id => lifecycles.value[id]?.revision > 0)
    jobs.value.unshift(job)
  }
  function enqueue(kind: InvestigationJob['kind'], key: string) {
    submissionError.value = ''
    const job = prepareJob(kind, key, now.value)
    if (!job) return null
    const existing = conflictingJob(job)
    if (existing) return existing
    if (!hasCapacity(job)) return null
    if (jobs.value.length >= MAX_REPORT_JOBS) {
      submissionError.value = 'このセッションの解析履歴は上限の100件に達しています。'
      return null
    }
    // Register content and repository links only after the request is accepted.
    accept(job)
    return job
  }
  function submit(input: string) {
    const parsed = normalizeReportInput(input)
    if (!parsed.ok) { submissionError.value = parsed.message; return }
    enqueue('submission', parsed.key)
  }
  function reanalyze(id: string) { return enqueue('reanalysis', id) }
  function scanRepository(url: string) { return enqueue('repository', url) }
  function retry(id: string) {
    const job = jobs.value.find(job => job.id === id)
    if (!job || job.status !== 'failed') return
    submissionError.value = ''
    if (conflictingJob(job)) { submissionError.value = '同じ情報を解析中です。完了後にもう一度お試しください。'; return }
    if (!hasCapacity(job)) return
    job.status = 'queued'; job.createdAt = now.value; delete job.error
  }
  function cancel(id: string) {
    const job = jobs.value.find(job => job.id === id)
    if (job && active(job)) job.status = 'cancelled'
  }
  function renew(id: string) {
    const lifecycle = lifecycles.value[id]
    if (!Object.hasOwn(lifecycles.value, id) || !lifecycle) return
    lifecycles.value[id] = renewReportTracking(lifecycle, now.value)
    renewals.value[id] = now.value
  }
  function publish() {
    publishedIds.value = [...new Set([...publishedIds.value, ...publicationQueue.value])]
    publicationQueue.value = []
  }
  function repositoryItems(url: string) {
    const parsed = parseRepositoryUrl(url)
    const profile = parsed.ok ? repositoryFeedFor(parsed.label) : []
    return catalog.value.filter(item => parsed.ok && repositoryLinks.value[parsed.url]?.includes(item.id)).map(item => {
      const match = profile.find(candidate => candidate.id === item.id)
      return { ...item, ...match, repositoryAnalysis: match?.repositoryAnalysis ?? item.repositoryAnalysis ?? 'pending' as const }
    })
  }
  function additions(url: string) {
    return url ? repositoryItems(url) : catalog.value.filter(item => publishedIds.value.includes(item.id))
  }
  function activeJobFor(id: string) { return jobs.value.find(job => active(job) && job.reportIds.includes(id)) }
  function scanFor(url: string) { const parsed = parseRepositoryUrl(url); return parsed.ok ? jobs.value.find(job => job.kind === 'repository' && job.key === parsed.url) : undefined }

  // Restore request metadata and local lifecycle history, never serialized report content.
  try {
    // The legacy unowned key cannot safely be assigned to any profile or guest.
    const raw = sessions.get(storageKey) ?? sessionStorage.getItem(storageKey)
    if (raw) {
      if (raw.length >= MAX_REPORT_SESSION_LENGTH) throw new Error('Session exceeds the storage limit')
      const state: unknown = JSON.parse(raw)
      if (!isRecord(state)) throw new Error('Invalid report session')
      // A reload is not a new publication. Keep the local edition's timestamp.
      if (isStoredDate(state.periodicPublishedAt) && state.periodicPublishedAt <= now.value) {
        periodicReport.publishedAt = state.periodicPublishedAt
        periodicReport.updatedAt = state.periodicPublishedAt
        lifecycles.value[periodicReport.id] = createReportLifecycle(periodicReport, now.value)
      }
      for (const row of parseStoredJobs(state.jobs, now.value).reverse()) {
        const job = prepareJob(row.kind, row.key, row.createdAt)
        if (!job) continue
        job.status = row.status
        const shouldFinish = row.status === 'completed' || (active(job) && Date.now() - Date.parse(row.createdAt) >= jobDuration)
        if (shouldFinish) job.status = 'completed'
        if (conflictingJob(job) || (active(job) && jobs.value.filter(active).length >= MAX_ACTIVE_REPORT_JOBS)) continue
        if (job.status === 'failed') job.error = '解析を完了できませんでした。再試行してください。'
        accept(job)
        if (shouldFinish) finish(job, new Date(Math.min(Date.now(), Date.parse(row.createdAt) + jobDuration)).toISOString())
      }
      const restoredLifecycles = new Set<string>()
      if (isRecord(state.lifecycles)) for (const [id, value] of Object.entries(state.lifecycles)) {
        if (!Object.hasOwn(lifecycles.value, id)) continue
        const lifecycle = parseStoredLifecycle(value, lifecycles.value[id]!, now.value)
        if (!lifecycle) continue
        restoredLifecycles.add(id)
        lifecycles.value[id] = lifecycle
      }
      if (isRecord(state.renewals)) for (const [id, at] of Object.entries(state.renewals)) {
        if (Object.hasOwn(lifecycles.value, id) && isStoredDate(at) && at <= now.value) {
          if (!restoredLifecycles.has(id)) lifecycles.value[id] = renewReportTracking(lifecycles.value[id]!, at)
          renewals.value[id] = at
        }
      }
      if (Array.isArray(state.publishedIds)) publishedIds.value = [...new Set(state.publishedIds.slice(0, MAX_REPORT_JOBS).filter((id): id is string => typeof id === 'string' && Object.hasOwn(lifecycles.value, id) && lifecycles.value[id]!.revision > 0))]
      if (Array.isArray(state.publicationQueue)) {
        const queued = state.publicationQueue.slice(0, MAX_REPORT_JOBS).filter((id): id is string => typeof id === 'string'
          && Object.hasOwn(lifecycles.value, id) && lifecycles.value[id]!.revision > 0)
        publicationQueue.value = [...new Set([...publicationQueue.value, ...queued])]
      }
      publicationQueue.value = publicationQueue.value.filter(id => !publishedIds.value.includes(id))
    }
  } catch { storageError.value = '解析履歴を読み込めませんでした。この画面では新しく依頼できます。' }
  function persist() {
    try {
      const savedLifecycles = Object.fromEntries(Object.entries(lifecycles.value).map(([id, lifecycle]) => [id, { ...lifecycle, history: lifecycle.history.slice(-MAX_REPORT_JOBS) }]))
      const raw = JSON.stringify({ periodicPublishedAt: periodicReport.publishedAt, jobs: jobs.value, publishedIds: publishedIds.value, publicationQueue: publicationQueue.value, renewals: renewals.value, lifecycles: savedLifecycles })
      if (raw.length >= MAX_REPORT_SESSION_LENGTH) throw new Error('Session exceeds the storage limit')
      sessions.set(storageKey, raw)
      sessionStorage.setItem(storageKey, raw)
    } catch { storageError.value = '解析履歴を保存できません。ページを閉じると今回の履歴が失われます。' }
  }
  watch([jobs, publishedIds, publicationQueue, renewals, lifecycles], persist, { deep: true })

  const began = Date.parse(periodicReport.publishedAt)
  let editionQueued = publicationQueue.value.includes(periodicReport.id) || publishedIds.value.includes(periodicReport.id)
  const timer = setInterval(() => {
    now.value = new Date().toISOString()
    if (document.visibilityState === 'hidden') return
    for (const job of jobs.value.filter(active)) {
      const elapsed = Date.now() - Date.parse(job.createdAt)
      if (elapsed >= jobDuration) finish(job, now.value)
      else job.status = elapsed >= 3000 ? 'analyzing' : elapsed >= 1000 ? 'collecting' : 'queued'
    }
    for (const [id, lifecycle] of Object.entries(lifecycles.value)) {
      if (lifecycle.revision > 0 && isTrackingActive(lifecycle, now.value) && lifecycle.nextCheckAt && lifecycle.nextCheckAt <= now.value && !activeJobFor(id)) lifecycles.value[id] = updateReportLifecycle(lifecycle, now.value, 'scheduled')
    }
    if (!editionQueued && Date.now() - began >= 30_000 && !publishedIds.value.includes(periodicReport.id)) {
      editionQueued = true
      publicationQueue.value.push(periodicReport.id)
    }
  }, 1000)
  onScopeDispose(() => {
    clearInterval(timer)
    persist()
  })
  return { now, jobs, catalog, referenceFor, lifecycles, reports, publicationQueue, submissionError, storageError, submit, reanalyze, renew, retry, cancel, publish, scanRepository, scanFor, additions, activeJobFor, repositoryItems,
    knownRepositoryItems: (url: string) => { const parsed = parseRepositoryUrl(url); return parsed.ok ? repositoryFeedFor(parsed.label) : [] },
  }
}
