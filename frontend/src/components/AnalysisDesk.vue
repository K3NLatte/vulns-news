<script setup lang="ts">
import { TRACKING_DAYS } from '../services/reports'
import { computed, nextTick, ref } from 'vue'
import { ArrowLeft } from '@lucide/vue'
import { articlePath } from '../composables/useNavigation'
import type { FeedItem } from '../types/feed'
import type { InvestigationJob } from '../types/investigation'
import type { ReportLifecycle, ReportUpdateReason } from '../types/reports'

const props = defineProps<{
  jobs: InvestigationJob[]
  reports: { item: FeedItem; lifecycle: ReportLifecycle }[]
  submissionError: string
  now: string
  trackingFilter: 'active' | 'expired'
}>()

const emit = defineEmits<{
  submit: [input: string]
  reanalyze: [id: string]
  renew: [id: string]
  retry: [id: string]
  cancel: [id: string]
  'update:tracking-filter': [value: 'active' | 'expired']
  'open-report': [linkId: string]
}>()

const input = ref('')
const inputField = ref<HTMLInputElement | null>(null)

async function submit() {
  emit('submit', input.value)
  await nextTick()
  if (props.submissionError) inputField.value?.focus()
}

async function cancelJob(job: InvestigationJob, event: MouseEvent) {
  const entry = (event.currentTarget as HTMLElement).closest('.request-entry')
  emit('cancel', job.id)
  await nextTick()
  // The cancel action disappears after success; keep keyboard focus in this request.
  entry?.querySelector<HTMLElement>('h3')?.focus({ preventScroll: true })
}
const dateFormat = new Intl.DateTimeFormat('ja-JP', {
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo',
})
const statusLabels: Record<InvestigationJob['status'], string> = {
  queued: '解析待ち',
  collecting: '情報を取得中',
  analyzing: 'レポートを作成中',
  completed: '完了',
  failed: '解析に失敗',
  cancelled: '中止済み',
}
const revisionLabels: Record<ReportUpdateReason, string> = { initial: '初回分析', scheduled: '定期更新', manual: 'リクエストによる再分析' }
const kindLabels: Record<InvestigationJob['kind'], string> = {
  submission: '脆弱性の分析', reanalysis: '再分析', repository: 'リポジトリの調査',
}

function isActive(job: InvestigationJob) {
  return job.status === 'queued' || job.status === 'collecting' || job.status === 'analyzing'
}

function isTracking(report: ReportLifecycle) {
  return Boolean(report.trackingUntil && Date.parse(report.trackingUntil) > Date.parse(props.now))
}

function displayDate(value: string | null | undefined) {
  if (!value || !Number.isFinite(Date.parse(value))) return '未設定'
  return dateFormat.format(new Date(value))
}

const activeReports = computed(() => props.reports.filter(report => isTracking(report.lifecycle)))
const expiredReports = computed(() => props.reports.filter(report => !isTracking(report.lifecycle)))
const visibleReports = computed(() => props.trackingFilter === 'active' ? activeReports.value : expiredReports.value)
const reportTitles = computed(() => new Map(props.reports.map(({ item }) => [item.id, item.title])))
const activeReportIds = computed(() => new Set(props.jobs.filter(isActive).flatMap(job => job.reportIds)))
</script>

<template>
  <div class="analysis-desk">
    <header class="page-heading">
      <h1>脆弱性を分析</h1>
      <a class="text-button" href="#/feed"><ArrowLeft :size="17" aria-hidden="true" />フィードへ</a>
    </header>

    <form class="submission-form" @submit.prevent="submit">
      <label for="analysis-input">CVE・GHSA・アドバイザリURL</label>
      <div class="submission-row">
        <input
          id="analysis-input"
          ref="inputField"
          v-model="input"
          type="text"
          autocomplete="off"
          autocapitalize="off"
          :spellcheck="false"
          maxlength="2048"
          required
          placeholder="CVE-2026-12345"
          :aria-invalid="submissionError ? true : undefined"
          :aria-describedby="submissionError ? 'analysis-input-help analysis-input-error' : 'analysis-input-help'"
        />
        <button class="primary-button" type="submit">解析する</button>
      </div>
      <p id="analysis-input-help" class="field-help">CVE番号、GHSA番号、公開アドバイザリのHTTPS URLに対応しています。</p>
      <p v-if="submissionError" id="analysis-input-error" class="input-error" role="alert">{{ submissionError }}</p>
    </form>

    <section v-if="jobs.length" class="desk-section requests-section" aria-labelledby="analysis-requests-heading">
      <h2 id="analysis-requests-heading">解析の依頼</h2>
      <ul class="request-list">
        <li v-for="job in jobs" :key="job.id" class="request-entry">
          <div class="request-main">
            <div class="request-meta"><span>{{ kindLabels[job.kind] }}</span><time :datetime="job.createdAt">{{ displayDate(job.createdAt) }}</time></div>
            <h3 tabindex="-1">{{ job.label }}</h3>
            <p class="request-state" :class="'state-' + job.status" role="status" aria-atomic="true"><span class="sr-only">{{ job.label }}： </span>{{ statusLabels[job.status] }}</p>
            <p v-if="job.error && job.status === 'failed'" class="input-error">{{ job.error }}</p>
            <p v-if="job.kind === 'repository' && (job.reusedCount || job.newCount || job.status === 'completed')" class="request-result-counts">
              <span>既存レポート {{ job.reusedCount }}件</span><span>新規作成 {{ job.newCount }}件</span>
            </p>
            <p v-else-if="job.status === 'completed' && job.reusedCount" class="field-help">既存のレポートが見つかりました。</p>
            <ul v-if="job.reportIds.some(id => reportTitles.has(id))" class="request-reports" aria-label="参照できるレポート">
              <li v-for="id in job.reportIds.filter(id => reportTitles.has(id))" :key="id"><a :id="'request-report-' + job.id + '-' + id" :href="articlePath(id)" @click="emit('open-report', 'request-report-' + job.id + '-' + id)">{{ reportTitles.get(id) || 'レポートを開く' }}</a></li>
            </ul>
          </div>
          <div v-if="isActive(job) || job.status === 'failed'" class="request-actions">
            <button v-if="isActive(job)" class="secondary-button" type="button" :aria-label="job.label + 'の解析を中止'" @click="cancelJob(job, $event)">中止</button>
            <button v-else class="secondary-button" type="button" :aria-label="job.label + 'の解析を再試行'" @click="emit('retry', job.id)">再試行</button>
          </div>
        </li>
      </ul>
    </section>

    <section class="desk-section tracking-section" aria-labelledby="report-tracking-heading">
      <h2 id="report-tracking-heading">レポートの追跡</h2>
      <div class="tracking-filters" role="group" aria-label="追跡状態">
        <button type="button" :aria-pressed="trackingFilter === 'active'" @click="emit('update:tracking-filter', 'active')">追跡中 <span>{{ activeReports.length }}</span></button>
        <button type="button" :aria-pressed="trackingFilter === 'expired'" @click="emit('update:tracking-filter', 'expired')">期限終了 <span>{{ expiredReports.length }}</span></button>
      </div>
      <p v-if="!visibleReports.length" class="tracking-empty">{{ trackingFilter === 'active' ? '追跡中のレポートはありません。' : '追跡期限が終了したレポートはありません。' }}</p>
      <ul v-else class="report-list">
        <li v-for="{ item, lifecycle } in visibleReports" :key="item.id" class="report-entry">
          <div class="report-main">
            <p class="report-identifier"><span>{{ item.advisoryId }}</span><span v-if="lifecycle.revision > 0">第{{ lifecycle.revision }}版</span></p>
            <h3><a :id="'tracked-report-' + item.id" :href="articlePath(item.id)" @click="emit('open-report', 'tracked-report-' + item.id)">{{ item.title }}</a></h3>
            <dl class="report-dates">
              <div><dt>最終分析</dt><dd><time v-if="lifecycle.lastAnalyzedAt" :datetime="lifecycle.lastAnalyzedAt">{{ displayDate(lifecycle.lastAnalyzedAt) }}</time><span v-else>未分析</span></dd></div>
              <div><dt>追跡期限</dt><dd><time v-if="lifecycle.trackingUntil" :datetime="lifecycle.trackingUntil">{{ displayDate(lifecycle.trackingUntil) }}</time><span v-else>なし</span></dd></div>
              <div v-if="isTracking(lifecycle) && lifecycle.nextCheckAt"><dt>次回確認</dt><dd><time :datetime="lifecycle.nextCheckAt">{{ displayDate(lifecycle.nextCheckAt) }}</time></dd></div>
            </dl>
            <p v-if="!isTracking(lifecycle)" class="tracking-expired-note">自動更新は終了しています。レポートは引き続き閲覧できます。</p>
            <details v-if="lifecycle.history.length" class="report-history">
              <summary>更新履歴</summary>
              <ol>
                <li v-for="entry in lifecycle.history" :key="entry.revision">
                  <div class="history-meta"><span>第{{ entry.revision }}版</span><time :datetime="entry.analyzedAt">{{ displayDate(entry.analyzedAt) }}</time></div>
                  <p>{{ revisionLabels[entry.reason] }}</p>
                </li>
              </ol>
            </details>
          </div>
          <div class="report-actions">
            <button class="secondary-button" type="button" :disabled="activeReportIds.has(item.id)" :aria-label="item.advisoryId + 'を再分析'" @click="emit('reanalyze', item.id)">{{ activeReportIds.has(item.id) ? '解析中' : '再分析' }}</button>
            <button v-if="!isTracking(lifecycle)" class="text-button" type="button" :aria-label="item.advisoryId + 'の追跡を' + TRACKING_DAYS + '日間再開'" @click="emit('renew', item.id)">{{ TRACKING_DAYS }}日間追跡を再開</button>
          </div>
        </li>
      </ul>
    </section>
  </div>
</template>

<style scoped>
.analysis-desk { max-width: 1100px; margin: 0 auto; }
.submission-form { border-top: 2px solid var(--ink); padding: 28px 0; }
.submission-form > label { display: block; font-weight: 600; margin-bottom: 12px; }
.submission-row { display: flex; gap: 12px; }
.submission-row input { flex: 1; min-width: 0; width: 100%; }
.submission-row button { flex-shrink: 0; }
.field-help { margin-top: 10px; color: var(--muted); font-size: .875rem; line-height: 1.7; }
.desk-section { margin-top: 32px; }
.desk-section h2 { margin-bottom: 16px; }
.request-list, .report-list { padding: 0; margin: 0; list-style: none; border-top: 1px solid var(--line); }
.request-entry, .report-entry { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px 28px; padding: 24px 0; border-bottom: 1px solid var(--line); }
.request-main, .report-main { min-width: 0; flex: 1; }
.request-meta, .report-identifier, .history-meta { display: flex; align-items: baseline; flex-wrap: wrap; gap: 6px 20px; color: var(--muted); font-size: .875rem; line-height: 1.7; }
.request-entry h3, .report-entry h3 { margin-top: 8px; overflow-wrap: anywhere; }
.report-identifier > span:first-child { font-family: var(--mono); }
.report-entry h3 a { color: var(--ink); text-decoration: none; }
.report-entry h3 a:hover { color: var(--accent); text-decoration: underline; }
.request-state { margin-top: 10px; font-size: .875rem; line-height: 1.7; font-weight: 600; color: var(--accent); }
.state-completed { color: var(--low-ink); }
.state-failed { color: var(--critical); }
.state-cancelled { color: var(--muted); }
.request-result-counts { display: flex; flex-wrap: wrap; gap: 6px 20px; margin-top: 8px; font-size: .875rem; line-height: 1.7; color: var(--muted); }
.request-reports { margin: 12px 0 0; padding-left: 20px; }
.request-reports li { padding-block: 4px; line-height: 1.8; overflow-wrap: anywhere; }
.request-actions, .report-actions { display: flex; flex-wrap: wrap; gap: 8px 16px; flex-shrink: 0; }
.report-actions { flex-direction: column; align-items: flex-end; }
.tracking-filters { display: flex; flex-wrap: wrap; gap: 12px 28px; margin-bottom: 0; }
.tracking-filters button { padding: 10px 0 12px; min-height: 44px; display: inline-flex; align-items: center; gap: 10px; border: 0; border-bottom: 3px solid transparent; background: transparent; color: var(--muted); }
.tracking-filters button[aria-pressed='true'] { border-bottom-color: var(--accent); color: var(--ink); font-weight: 600; }
.tracking-filters button:hover { color: var(--accent); }
.tracking-filters span { font-variant-numeric: tabular-nums; font-size: .875rem; }
.report-dates { display: flex; flex-wrap: wrap; gap: 12px 32px; margin: 18px 0 0; }
.report-dates dt { color: var(--muted); font-size: .875rem; margin-bottom: 4px; }
.report-dates dd { margin: 0; font-size: .875rem; line-height: 1.7; }
.tracking-expired-note { color: var(--muted); margin-top: 14px; font-size: .875rem; line-height: 1.7; }
.tracking-empty { border-top: 1px solid var(--line); padding-block: 32px; color: var(--muted); line-height: 1.8; }
.report-history { margin-top: 10px; }
.report-history summary { cursor: pointer; width: fit-content; min-height: 44px; padding-block: 10px; color: var(--accent); font-size: .875rem; }
.report-history summary:hover { color: var(--accent-hover); }
.report-history ol { margin: 0; padding-left: 24px; }
.report-history li { padding-block: 8px; }
.report-history li + li { border-top: 1px solid var(--line); }
.report-history li p { margin-top: 4px; line-height: 1.8; font-size: .875rem; overflow-wrap: anywhere; }
@media (max-width: 699px) {
  .submission-form { padding-block: 24px; }
  .submission-row { flex-wrap: wrap; }
  .submission-row input { flex-basis: 100%; }
  .submission-row button { margin-left: auto; }
  .request-entry, .report-entry { flex-wrap: wrap; gap: 16px; }
  .request-main, .report-main { flex-basis: 100%; }
  .request-actions, .report-actions { flex-direction: row; align-items: center; width: 100%; }
  .report-dates { gap: 14px 24px; }
  .desk-section { margin-top: 28px; }
}
</style>
