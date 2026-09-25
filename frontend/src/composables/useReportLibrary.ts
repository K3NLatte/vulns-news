import { computed, effectScope, onScopeDispose, ref, shallowRef, toValue, watch, type MaybeRefOrGetter } from 'vue'
import { mockFeed, repositoryFeedFor } from '../mocks/feed'
import { parseRepositoryUrl } from '../utils/repositoryUrl'
import { localId } from '../utils/localId'
import { acceptLocalReportCommand } from '../services/reportCommands'
import { createReportLifecycle, createSubmittedReport, findExistingReport, getSavedReportItems, historicalReports, isTrackingActive, normalizeReportInput, renewReportTracking, updateReportLifecycle } from '../services/reports'
import type { FeedItem } from '../types/feed'
import type { InvestigationJob } from '../types/investigation'
import type { ReportActionResult, ReportCommand, ReportCommandAdapter, ReportLifecycle, SavedReportReference } from '../types/reports'
import { isRecord, isStoredDate, MAX_ACTIVE_REPORT_JOBS, MAX_REPORT_JOBS, MAX_REPORT_SESSION_LENGTH, parseStoredJobs, parseStoredLifecycle } from '../services/reportSession'

const storagePrefix = 'vulns-news-report-lab-v2'
const active = (job: InvestigationJob) => ['queued', 'collecting', 'analyzing'].includes(job.status)
// Local scenario timing, independent of backend progress or scheduling contracts.
const jobDuration = 6000

/** Each browser-local profile owns its requests, results and tracking state. */
export function useReportLibrary(owner: MaybeRefOrGetter<string | null | undefined> = null, enabled = true, admit: ReportCommandAdapter = acceptLocalReportCommand) {
  // Keep current-tab work available across profile switches even when storage fails.
  const sessions = new Map<string, string>()
  const keyForOwner = () => {
    const id = toValue(owner)
    return id == null ? `${storagePrefix}:guest` : `${storagePrefix}:user:${encodeURIComponent(id)}`
  }
  let disposed = false
  const pending = ref(false)
  let requestController: AbortController | undefined
  let scope = effectScope()
  const current = shallowRef(scope.run(() => createReportLibrary(keyForOwner(), sessions, enabled))!)
  watch(keyForOwner, key => {
    requestController?.abort()
    requestController = undefined
    pending.value = false
    // Disposal saves pending changes for the old owner and stops its queued watchers
    // and timer before any new-owner state becomes available.
    scope.stop()
    scope = effectScope()
    current.value = scope.run(() => createReportLibrary(key, sessions, enabled))!
  }, { flush: 'sync' })
  onScopeDispose(() => {
    disposed = true
    requestController?.abort()
    scope.stop()
  })

  async function execute<T extends { ok: boolean }>(
    command: ReportCommand,
    operation: (library: ReturnType<typeof createReportLibrary>) => T,
  ): Promise<T | Extract<ReportActionResult, { ok: false }>> {
    const failure = (reason: Extract<ReportActionResult, { ok: false }>['reason'], message: string) => ({ ok: false as const, reason, message })
    const library = current.value
    if (!enabled || disposed) return failure('invalid', 'この構成では追加解析を利用できません。')
    if (pending.value) return failure('busy', '前の操作を受け付けています。しばらくお待ちください。')
    if (command.kind === 'submit' || command.kind === 'scanRepository') {
      const parsed = command.kind === 'submit' ? normalizeReportInput(command.key) : parseRepositoryUrl(command.key)
      if (!parsed.ok) { library.setCommandError(command, parsed.message); return failure('invalid', parsed.message) }
      command = { ...command, key: 'key' in parsed ? parsed.key : parsed.url }
    }
    const controller = new AbortController()
    requestController = controller
    pending.value = true
    let timeout: ReturnType<typeof setTimeout> | undefined
    let rejectAbort: (() => void) | undefined
    try {
      const approval = await Promise.race([
        admit(command, { signal: controller.signal }),
        new Promise<never>((_, reject) => {
          rejectAbort = () => reject(new Error('aborted'))
          controller.signal.addEventListener('abort', rejectAbort, { once: true })
          timeout = setTimeout(() => controller.abort(), 15_000)
        }),
      ])
      if (controller.signal.aborted || current.value !== library || disposed) return failure('aborted', '利用者が切り替わったため、操作を中止しました。')
      if (!approval.ok) {
        const message = approval.reason === 'conflict' ? '対象が更新されています。最新の状態を確認してから再試行してください。'
          : approval.reason === 'capacity' ? '受付上限に達しています。しばらくしてから再試行してください。'
            : '依頼を受け付けられませんでした。接続を確認して再試行してください。'
        library.setCommandError(command, message)
        return failure(approval.reason, message)
      }
      library.clearCommandError(command)
      const result = operation(library)
      if (!result.ok && 'message' in result && typeof result.message === 'string') library.setCommandError(command, result.message)
      return result
    } catch {
      if (current.value !== library || disposed) return failure('aborted', '利用者が切り替わったため、操作を中止しました。')
      const message = '依頼を受け付けられませんでした。接続を確認して再試行してください。'
      library.setCommandError(command, message)
      return failure('network', message)
    } finally {
      if (timeout !== undefined) clearTimeout(timeout)
      if (rejectAbort) controller.signal.removeEventListener('abort', rejectAbort)
      if (requestController === controller) {
        requestController = undefined
        pending.value = false
      }
    }
  }
  const commands = {
    submit: (key: string) => execute({ kind: 'submit', key }, library => library.submit(key)),
    reanalyze: (key: string) => execute({ kind: 'reanalyze', key }, library => library.reanalyze(key)),
    scanRepository: (key: string) => execute({ kind: 'scanRepository', key }, library => library.scanRepository(key)),
    retry: (key: string) => execute({ kind: 'retry', key }, library => library.retry(key)),
    cancel: (key: string) => execute({ kind: 'cancel', key }, library => library.cancel(key)),
    renew: (key: string) => execute({ kind: 'renew', key }, library => library.renew(key)),
    dismissJob: (key: string) => execute({ kind: 'dismissJob', key }, library => library.dismissJob(key) ? { ok: true as const } : { ok: false as const, reason: 'invalid' as const, message: '削除できる依頼がありません。' }),
  }


  return {
    commands, pending,
    now: computed(() => current.value.now.value),
    jobs: computed(() => current.value.jobs.value),
    catalog: computed(() => current.value.catalog.value),
    lifecycles: computed(() => current.value.lifecycles.value),
    reports: computed(() => current.value.reports.value),
    publicationQueue: computed(() => current.value.publicationQueue.value),
    submissionError: computed(() => current.value.submissionError.value),
    submissionMessage: computed(() => current.value.submissionMessage.value),
    operationErrors: computed(() => current.value.operationErrors.value),
    dismissJob: (id: string) => current.value.dismissJob(id),
    clearSubmissionFeedback: () => current.value.clearSubmissionFeedback(),
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

function createReportLibrary(storageKey: string, sessions: Map<string, string>, enabled: boolean) {
  const now = ref(new Date().toISOString())
  const jobs = ref<InvestigationJob[]>([])
  const created = ref<FeedItem[]>([])
  const lifecycles = ref<Record<string, ReportLifecycle>>({})
  const baselineLifecycles = new Map<string, string>()
  const repositoryLinks = ref<Record<string, string[]>>({})
  const publishedIds = ref<string[]>([])
  const publicationQueue = ref<string[]>([])
  const renewals = ref<Record<string, string>>({})
  const references = ref<Record<string, SavedReportReference>>({})
  const operationErrors = ref<Record<string, string>>({})
  const submissionMessage = ref('')
  const submissionError = ref('')
  const storageError = ref('')
  const periodicReport: FeedItem = { ...structuredClone(mockFeed[0]!), id: 'demo-013', advisoryId: 'DEMO-2026-013', title: 'テンプレート評価の追加調査と修正版の検証', publishedAt: '2026-09-25T03:00:00.000Z', updatedAt: '2026-09-25T03:00:00.000Z' }
  const catalog = computed(() => [...mockFeed, ...historicalReports, periodicReport, ...created.value])
  function registerLifecycle(item: FeedItem, at: string, origin: ReportLifecycle['origin'] = 'feed') {
    const lifecycle = createReportLifecycle(item, at, origin)
    lifecycles.value[item.id] = lifecycle
    baselineLifecycles.set(item.id, JSON.stringify(lifecycle))
  }
  for (const item of catalog.value) registerLifecycle(item, now.value)
  const reports = computed(() => catalog.value.filter(item => ((lifecycles.value[item.id]?.revision ?? 0) > 0 && item.id !== periodicReport.id) || publishedIds.value.includes(item.id) || jobs.value.some(job => job.status === 'completed' && job.reportIds.includes(item.id))).map(item => ({ item, lifecycle: lifecycles.value[item.id]! })))

  function referenceFor(id: string): SavedReportReference | undefined {
    return references.value[id]
  }

  function resolveSubmission(key: string, at: string) {
    const parsed = normalizeReportInput(key)
    if (!parsed.ok) return null
    const existing = findExistingReport(parsed.key, catalog.value)
    if (existing) return { item: existing, reused: (lifecycles.value[existing.id]?.revision ?? 0) > 0 }
    const item = createSubmittedReport(parsed.key, parsed.kind, at)
    return { item, reused: false }
  }

  function prepareJob(kind: InvestigationJob['kind'], key: string, at: string): InvestigationJob | null {
    let reportIds: string[]
    let reusedCount = 0
    let label: string
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
      reusedCount = reportIds.filter(id => (lifecycles.value[id]?.revision ?? 0) > 0).length
    } else {
      const item = catalog.value.find(item => item.id === key)
      if (!item) return null
      reportIds = [item.id]
      label = item.advisoryId
    }
    return { id: localId(), key, label, kind, status: kind === 'submission' && reusedCount ? 'completed' : 'queued', createdAt: at, reportIds, reusedCount, newCount: kind === 'reanalysis' ? 0 : reportIds.length - reusedCount }
  }

  function finish(job: InvestigationJob, at: string, applyAnalysis = true) {
    for (const id of job.reportIds) {
      const lifecycle = lifecycles.value[id]
      if (!lifecycle) continue
      const report = catalog.value.find(item => item.id === id)
      // Completing the local workflow cannot manufacture an analysis for unknown facts.
      if (applyAnalysis && report?.assessment !== 'unverified' && (job.kind === 'reanalysis' || lifecycle.revision === 0)) {
        lifecycles.value[id] = updateReportLifecycle(lifecycle, at, 'manual')
      }
      if ((job.kind === 'submission' || references.value[id]) && !publishedIds.value.includes(id) && !mockFeed.some(item => item.id === id) && !publicationQueue.value.includes(id)) publicationQueue.value.push(id)
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
      return false
    }
    return true
  }
  function accept(job: InvestigationJob) {
    if (job.kind === 'submission') {
      const result = resolveSubmission(job.key, job.createdAt)
      if (result && !Object.hasOwn(lifecycles.value, result.item.id)) {
        created.value.push(result.item)
        references.value[result.item.id] = { input: job.key, createdAt: job.createdAt }
        registerLifecycle(result.item, job.createdAt, 'submitted')
      }
    }
    if (job.kind === 'repository') repositoryLinks.value[job.key] = job.reportIds.filter(id => (lifecycles.value[id]?.revision ?? 0) > 0)
    jobs.value.unshift(job)
  }
  function enqueue(kind: InvestigationJob['kind'], key: string): ReportActionResult {
    if (!enabled) return { ok: false, reason: 'invalid', message: 'この構成では追加解析を利用できません。' }
    const job = prepareJob(kind, key, new Date().toISOString())
    if (!job) return { ok: false, reason: 'invalid', message: '依頼する対象を確認してください。' }
    const existing = conflictingJob(job) ?? (kind === 'submission'
      ? jobs.value.find(current => current.kind === 'submission' && current.status === 'completed'
        && current.reportIds.some(id => job.reportIds.includes(id))) : undefined)
    if (existing) return { ok: true, job: existing, status: 'duplicate' }
    if (!hasCapacity(job)) return { ok: false, reason: 'capacity', message: '同時に依頼できるのは5件までです。完了後にもう一度お試しください。' }
    if (jobs.value.length >= MAX_REPORT_JOBS) {
      return { ok: false, reason: 'history', message: '解析履歴は100件までです。終了した履歴を削除してから依頼してください。' }
    }
    accept(job)
    return { ok: true, job, status: job.status === 'completed' ? 'reused' : 'accepted' }
  }
  function clearCommandError(command: ReportCommand) {
    if (command.kind === 'submit') clearSubmissionFeedback()
    else delete operationErrors.value[command.key]
  }
  function setCommandError(command: ReportCommand, message: string) {
    if (command.kind === 'submit') { submissionError.value = message; submissionMessage.value = '' }
    else operationErrors.value[command.key] = message
  }
  function clearSubmissionFeedback() {
    submissionError.value = ''
    submissionMessage.value = ''
  }
  function submit(input: string): ReportActionResult {
    clearSubmissionFeedback()
    const parsed = normalizeReportInput(input)
    const result: ReportActionResult = parsed.ok ? enqueue('submission', parsed.key)
      : { ok: false, reason: 'invalid', message: parsed.message }
    if (!result.ok) submissionError.value = result.message
    else submissionMessage.value = result.status === 'duplicate' ? '同じ依頼が履歴にあります。'
      : result.status === 'reused' ? '既存のレポートを表示しました。' : '依頼を受け付けました。'
    return result
  }
  function reportOperation(key: string, operation: () => ReportActionResult) {
    delete operationErrors.value[key]
    const result = operation()
    if (!result.ok) operationErrors.value[key] = result.message
    return result
  }
  function reanalyze(id: string) { return reportOperation(id, () => enqueue('reanalysis', id)) }
  function scanRepository(url: string) {
    const parsed = parseRepositoryUrl(url)
    return reportOperation(parsed.ok ? parsed.url : url, () => enqueue('repository', url))
  }
  function retry(id: string): ReportActionResult {
    return reportOperation(id, () => {
      const job = jobs.value.find(job => job.id === id)
      if (!job || (job.status !== 'failed' && job.status !== 'cancelled')) return { ok: false, reason: 'invalid', message: '再試行できる依頼がありません。' }
      const existing = conflictingJob(job)
      if (existing) return { ok: true, job: existing, status: 'duplicate' }
      if (!hasCapacity(job)) return { ok: false, reason: 'capacity', message: '同時に依頼できるのは5件までです。完了後にもう一度お試しください。' }
      job.status = 'queued'
      job.startedAt = new Date().toISOString()
      delete job.error
      return { ok: true, job, status: 'accepted' }
    })
  }
  function dismissJob(id: string) {
    const job = jobs.value.find(item => item.id === id)
    if (!job || active(job)) return false
    jobs.value = jobs.value.filter(item => item.id !== id)
    delete operationErrors.value[id]
    for (const reportId of job.reportIds) {
      if (!references.value[reportId] || jobs.value.some(item => item.reportIds.includes(reportId))) continue
      created.value = created.value.filter(item => item.id !== reportId)
      delete references.value[reportId]
      delete lifecycles.value[reportId]
      baselineLifecycles.delete(reportId)
      delete renewals.value[reportId]
      publishedIds.value = publishedIds.value.filter(id => id !== reportId)
      publicationQueue.value = publicationQueue.value.filter(id => id !== reportId)
    }
    return true
  }
  function cancel(id: string) {
    const job = jobs.value.find(job => job.id === id)
    if (!job || !active(job)) return { ok: false as const, reason: 'invalid' as const, message: '実行中の依頼がありません。' }
    job.status = 'cancelled'
    return { ok: true as const }
  }
  function renew(id: string) {
    const lifecycle = lifecycles.value[id]
    if (!Object.hasOwn(lifecycles.value, id) || !lifecycle || lifecycle.revision === 0) return { ok: false as const, reason: 'invalid' as const, message: '分析結果があるレポートだけ追跡を延長できます。' }
    lifecycles.value[id] = renewReportTracking(lifecycle, new Date().toISOString())
    renewals.value[id] = new Date().toISOString()
    return { ok: true as const }
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
  function activeJobFor(id: string) { return jobs.value.find(job => active(job) && job.reportIds.includes(id) && (job.kind !== 'repository' || lifecycles.value[id]?.revision === 0)) }
  function scanFor(url: string) { const parsed = parseRepositoryUrl(url); return parsed.ok ? jobs.value.find(job => job.kind === 'repository' && job.key === parsed.url) : undefined }

  // Restore request metadata and local lifecycle history, never serialized report content.
  try {
    // The legacy unowned key cannot safely be assigned to any profile or guest.
    const raw = enabled ? sessions.get(storageKey) ?? sessionStorage.getItem(storageKey) : null
    if (raw) {
      if (raw.length >= MAX_REPORT_SESSION_LENGTH) throw new Error('Session exceeds the storage limit')
      const state: unknown = JSON.parse(raw)
      if (!isRecord(state)) throw new Error('Invalid report session')
      // A reload is not a new publication. Keep the local edition's timestamp.
      if (isStoredDate(state.periodicPublishedAt)) {
        periodicReport.publishedAt = state.periodicPublishedAt
        periodicReport.updatedAt = state.periodicPublishedAt
        registerLifecycle(periodicReport, now.value)
      }
      if (isRecord(state.references)) for (const [id, reference] of Object.entries(state.references).slice(0, MAX_REPORT_JOBS)) {
        const items = getSavedReportItems({ [id]: reference as SavedReportReference })
        if (!items[0]) continue
        created.value.push(items[0])
        references.value[id] = { input: (reference as SavedReportReference).input, createdAt: (reference as SavedReportReference).createdAt }
        registerLifecycle(items[0], (reference as SavedReportReference).createdAt, 'submitted')
      }
      const completedOnRestore: { job: InvestigationJob; at: string }[] = []
      for (const row of parseStoredJobs(state.jobs, now.value).reverse()) {
        const job = prepareJob(row.kind, row.key, row.createdAt)
        if (!job) continue
        job.status = row.status
        job.startedAt = row.startedAt ?? row.createdAt
        if (job.startedAt > now.value) job.startedAt = now.value
        const shouldFinish = row.status === 'completed' || (active(job) && Date.now() - Date.parse(job.startedAt) >= jobDuration)
        if (shouldFinish) job.status = 'completed'
        if (conflictingJob(job) || (active(job) && jobs.value.filter(active).length >= MAX_ACTIVE_REPORT_JOBS)) continue
        if (job.status === 'failed') job.error = '解析を完了できませんでした。再試行してください。'
        accept(job)
        if (shouldFinish) {
          const completedAt = new Date(Math.min(Date.now(), Date.parse(job.startedAt) + jobDuration)).toISOString()
          finish(job, completedAt, false)
          if (row.status !== 'completed') completedOnRestore.push({ job, at: completedAt })
        }
      }
      const restoredLifecycles = new Set<string>()
      if (isRecord(state.lifecycles)) for (const [id, value] of Object.entries(state.lifecycles)) {
        if (!Object.hasOwn(lifecycles.value, id)) continue
        const lifecycle = parseStoredLifecycle(value, lifecycles.value[id]!, now.value)
        if (!lifecycle) continue
        restoredLifecycles.add(id)
        lifecycles.value[id] = lifecycle
      }
      for (const completed of completedOnRestore) finish(completed.job, completed.at)
      if (isRecord(state.renewals)) for (const [id, at] of Object.entries(state.renewals)) {
        if (Object.hasOwn(lifecycles.value, id) && isStoredDate(at)) {
          if (!restoredLifecycles.has(id)) lifecycles.value[id] = renewReportTracking(lifecycles.value[id]!, at)
          renewals.value[id] = at
        }
      }
      if (Array.isArray(state.publishedIds)) publishedIds.value = [...new Set(state.publishedIds.slice(0, MAX_REPORT_JOBS).filter((id): id is string => typeof id === 'string' && Object.hasOwn(lifecycles.value, id) && (lifecycles.value[id]!.revision > 0 || jobs.value.some(job => job.status === 'completed' && job.reportIds.includes(id)))))]
      if (Array.isArray(state.publicationQueue)) {
        const queued = state.publicationQueue.slice(0, MAX_REPORT_JOBS).filter((id): id is string => typeof id === 'string'
          && Object.hasOwn(lifecycles.value, id) && (lifecycles.value[id]!.revision > 0 || jobs.value.some(job => job.status === 'completed' && job.reportIds.includes(id))))
        publicationQueue.value = [...new Set([...publicationQueue.value, ...queued])]
      }
      publicationQueue.value = publicationQueue.value.filter(id => !publishedIds.value.includes(id))
    }
  } catch { storageError.value = '解析履歴を読み込めませんでした。この画面では新しく依頼できます。' }
  function persist() {
    if (!enabled) return
    try {
      const savedLifecycles = Object.fromEntries(Object.entries(lifecycles.value).filter(([id, lifecycle]) => {
        return JSON.stringify(lifecycle) !== baselineLifecycles.get(id)
      }).map(([id, lifecycle]) => [id, { ...lifecycle, history: lifecycle.history.slice(-MAX_REPORT_JOBS) }]))
      const raw = JSON.stringify({ references: references.value, periodicPublishedAt: periodicReport.publishedAt, jobs: jobs.value, publishedIds: publishedIds.value, publicationQueue: publicationQueue.value, renewals: renewals.value, lifecycles: savedLifecycles })
      if (raw.length >= MAX_REPORT_SESSION_LENGTH) throw new Error('Session exceeds the storage limit')
      sessions.set(storageKey, raw)
      sessionStorage.setItem(storageKey, raw)
      storageError.value = ''
    } catch { storageError.value = '解析履歴を保存できません。ページを閉じると今回の履歴が失われます。' }
  }
  watch([jobs, references, publishedIds, publicationQueue, renewals, lifecycles], persist, { deep: true })

  const began = Date.now()
  let editionQueued = publicationQueue.value.includes(periodicReport.id) || publishedIds.value.includes(periodicReport.id)
  const timer = enabled ? setInterval(() => {
    if (document.visibilityState === 'hidden') return
    now.value = new Date().toISOString()
    for (const job of jobs.value.filter(active)) {
      const elapsed = Date.now() - Date.parse(job.startedAt ?? job.createdAt)
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
  }, 1000) : undefined
  onScopeDispose(() => {
    if (timer !== undefined) clearInterval(timer)
    persist()
  })
  return { now, jobs, catalog, referenceFor, lifecycles, reports, publicationQueue, submissionError, submissionMessage, setCommandError, clearCommandError, operationErrors, clearSubmissionFeedback, dismissJob, storageError, submit, reanalyze, renew, retry, cancel, publish, scanRepository, scanFor, additions, activeJobFor, repositoryItems,
    knownRepositoryItems: (url: string) => { const parsed = parseRepositoryUrl(url); return parsed.ok ? repositoryFeedFor(parsed.label) : [] },
  }
}
