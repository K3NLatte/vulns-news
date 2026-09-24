import { computed, onScopeDispose, ref, watch } from 'vue'
import { mockFeed, repositoryFeedFor } from '../mocks/feed'
import { parseRepositoryUrl } from '../services/feed'
import { createReportLifecycle, createSubmittedReport, findExistingReport, historicalReports, isTrackingActive, normalizeReportInput, renewReportTracking, updateReportLifecycle } from '../services/reports'
import type { FeedItem } from '../types/feed'
import type { InvestigationJob } from '../types/investigation'
import type { ReportLifecycle } from '../types/reports'

const storageKey = 'vulns-news-report-lab-v1'
const active = (job: InvestigationJob) => ['queued', 'collecting', 'analyzing'].includes(job.status)
// Local scenario timing, independent of backend progress or scheduling contracts.
const jobDuration = 6000
const validDate = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value))

export function useReportLibrary() {
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

  function ensureSubmitted(key: string, at: string) {
    const parsed = normalizeReportInput(key)
    if (!parsed.ok) return null
    const existing = findExistingReport(parsed.key, catalog.value)
    if (existing) return { item: existing, reused: lifecycles.value[existing.id]?.revision > 0 }
    const item = createSubmittedReport(parsed.key, parsed.kind, at)
    created.value.push(item)
    lifecycles.value[item.id] = createReportLifecycle(item, at, 'submitted')
    return { item, reused: false }
  }

  function prepareJob(kind: InvestigationJob['kind'], key: string, at: string): InvestigationJob | null {
    let reportIds: string[] = []
    let reusedCount = 0
    let label = key
    if (kind === 'submission') {
      const result = ensureSubmitted(key, at)
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
      repositoryLinks.value[key] = reportIds.filter(id => lifecycles.value[id]?.revision > 0)
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

  function enqueue(kind: InvestigationJob['kind'], key: string) {
    submissionError.value = ''
    const job = prepareJob(kind, key, now.value)
    if (!job) return null
    const existing = jobs.value.find(current => active(current) && (
      kind === 'repository' ? current.kind === kind && current.key === job.key
        : current.kind !== 'repository' && current.reportIds.some(id => job.reportIds.includes(id))
    ))
    if (existing) return existing
    if (job.status !== 'completed' && jobs.value.filter(active).length >= 5) { submissionError.value = '同時に依頼できるのは5件までです。完了後にもう一度お試しください。'; return null }
    jobs.value.unshift(job)
    return job
  }
  function submit(input: string) {
    const parsed = normalizeReportInput(input)
    if (!parsed.ok) { submissionError.value = parsed.message; return }
    enqueue('submission', parsed.key)
  }
  function reanalyze(id: string) { enqueue('reanalysis', id) }
  function scanRepository(url: string) { enqueue('repository', url) }
  function retry(id: string) {
    const job = jobs.value.find(job => job.id === id)
    if (!job || job.status !== 'failed') return
    job.status = 'queued'; job.createdAt = now.value; delete job.error
  }
  function cancel(id: string) {
    const job = jobs.value.find(job => job.id === id)
    if (job && active(job)) job.status = 'cancelled'
  }
  function renew(id: string) {
    const lifecycle = lifecycles.value[id]
    if (!lifecycle) return
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
    return catalog.value.filter(item => repositoryLinks.value[url]?.includes(item.id)).map(item => ({ ...item, ...profile.find(match => match.id === item.id), repositoryAnalysis: item.repositoryAnalysis ?? 'analyzed' as const }))
  }
  function additions(url: string) {
    return url ? repositoryItems(url) : catalog.value.filter(item => publishedIds.value.includes(item.id))
  }
  function activeJobFor(id: string) { return jobs.value.find(job => active(job) && job.reportIds.includes(id)) }
  function scanFor(url: string) { return jobs.value.find(job => job.kind === 'repository' && job.key === url) }

  // Persist only validated requests and IDs; never trust serialized HTML or report content.
  try {
    const raw = sessionStorage.getItem(storageKey)
    if (raw && raw.length < 200_000) {
      const saved: unknown = JSON.parse(raw)
      if (saved && typeof saved === 'object') {
        const state = saved as Record<string, unknown>
        if (Array.isArray(state.jobs)) for (const entry of state.jobs.slice(-100).reverse()) {
          if (!entry || typeof entry !== 'object') continue
          const row = entry as Record<string, unknown>
          if (!['submission', 'reanalysis', 'repository'].includes(String(row.kind)) || typeof row.key !== 'string' || row.key.length > 2048 || !validDate(row.createdAt)) continue
          const job = prepareJob(row.kind as InvestigationJob['kind'], row.key, row.createdAt)
          if (!job) continue
          if (row.status === 'cancelled') job.status = 'cancelled'
          else if (row.status === 'failed') { job.status = 'failed'; job.error = '解析を完了できませんでした。再試行してください。' }
          else if (row.status === 'completed' || Date.now() - Date.parse(row.createdAt) >= jobDuration) finish(job, new Date(Date.parse(row.createdAt) + jobDuration).toISOString())
          jobs.value.unshift(job)
        }
        if (Array.isArray(state.publishedIds)) publishedIds.value = state.publishedIds.filter((id): id is string => typeof id === 'string' && catalog.value.some(item => item.id === id))
        publicationQueue.value = publicationQueue.value.filter(id => !publishedIds.value.includes(id))
        const restoredLifecycles = new Set<string>()
        if (state.lifecycles && typeof state.lifecycles === 'object') for (const [id, value] of Object.entries(state.lifecycles)) {
          if (!lifecycles.value[id] || !value || typeof value !== 'object') continue
          const saved = value as Record<string, unknown>
          const history = saved.history
          if (saved.articleId !== id || !validDate(saved.trackingUntil) || !(saved.lastAnalyzedAt === null || validDate(saved.lastAnalyzedAt)) || !(saved.nextCheckAt === null || validDate(saved.nextCheckAt)) || !Number.isInteger(saved.revision) || Number(saved.revision) < 0 || !['feed', 'submitted', 'repository'].includes(String(saved.origin)) || !Array.isArray(history) || history.length > 100) continue
          if (!history.every(entry => entry && Number.isInteger(entry.revision) && entry.revision > 0 && validDate(entry.analyzedAt) && ['initial', 'scheduled', 'manual'].includes(entry.reason))) continue
          restoredLifecycles.add(id)
          lifecycles.value[id] = { articleId: id, trackingUntil: saved.trackingUntil, lastAnalyzedAt: saved.lastAnalyzedAt as string | null, nextCheckAt: saved.nextCheckAt as string | null, revision: Number(saved.revision), origin: saved.origin as ReportLifecycle['origin'], history: history.map(entry => ({ revision: entry.revision, analyzedAt: entry.analyzedAt, reason: entry.reason })) }
        }
        if (state.renewals && typeof state.renewals === 'object') for (const [id, at] of Object.entries(state.renewals)) {
          if (lifecycles.value[id] && validDate(at)) { if (!restoredLifecycles.has(id)) lifecycles.value[id] = renewReportTracking(lifecycles.value[id]!, at); renewals.value[id] = at }
        }
      }
    }
  } catch { storageError.value = '解析履歴を読み込めませんでした。この画面では新しく依頼できます。' }
  watch([jobs, publishedIds, renewals, lifecycles], () => {
    try {
      sessionStorage.setItem(storageKey, JSON.stringify({ jobs: jobs.value.slice(0, 100), publishedIds: publishedIds.value, renewals: renewals.value, lifecycles: lifecycles.value }))
    } catch { storageError.value = '解析履歴を保存できません。ページを閉じると今回の履歴が失われます。' }
  }, { deep: true })

  const began = Date.now()
  let editionQueued = false
  const timer = setInterval(() => {
    now.value = new Date().toISOString()
    if (document.visibilityState === 'hidden') return
    for (const job of jobs.value.filter(active)) {
      const elapsed = Date.now() - Date.parse(job.createdAt)
      if (elapsed >= jobDuration) finish(job, now.value)
      else job.status = elapsed >= 3000 ? 'analyzing' : elapsed >= 1000 ? 'collecting' : 'queued'
    }
    for (const [id, lifecycle] of Object.entries(lifecycles.value)) {
      if (isTrackingActive(lifecycle, now.value) && lifecycle.nextCheckAt && lifecycle.nextCheckAt <= now.value && !activeJobFor(id)) lifecycles.value[id] = updateReportLifecycle(lifecycle, now.value, 'scheduled')
    }
    if (!editionQueued && Date.now() - began >= 30_000 && !publishedIds.value.includes(periodicReport.id)) {
      editionQueued = true
      publicationQueue.value.push(periodicReport.id)
    }
  }, 1000)
  onScopeDispose(() => clearInterval(timer))
  return { now, jobs, catalog, lifecycles, reports, publicationQueue, submissionError, storageError, submit, reanalyze, renew, retry, cancel, publish, scanRepository, scanFor, additions, activeJobFor, repositoryItems,
    knownRepositoryItems: (url: string) => { const parsed = parseRepositoryUrl(url); return parsed.ok ? repositoryFeedFor(parsed.label) : [] },
  }
}