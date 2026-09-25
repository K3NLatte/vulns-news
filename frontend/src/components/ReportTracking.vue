<script setup lang="ts">
import { TRACKING_DAYS } from '../services/reports'
import { computed, ref, watch } from 'vue'
import { RefreshCw, ChevronDown } from '@lucide/vue'
import { isTrackingActive } from '../services/reports'
import type { ReportLifecycle } from '../types/reports'
import type { InvestigationJob } from '../types/investigation'
const props = defineProps<{ lifecycle: ReportLifecycle; now: string; job?: InvestigationJob }>()
defineEmits<{ reanalyze: []; renew: [] }>()
const tracking = computed(() => isTrackingActive(props.lifecycle, props.now))
const updateStatus = ref('')
watch(() => props.lifecycle.revision, (revision, previous) => {
  if (revision > previous) updateStatus.value = `レポートを第${revision}版に更新しました。`
})
const dateFormat = new Intl.DateTimeFormat('ja-JP', {
  year: 'numeric', month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Tokyo',
})
function date(value: string | null) {
  if (!value || !Number.isFinite(Date.parse(value))) return '未設定'
  return dateFormat.format(new Date(value))
}
</script>
<template>
  <section class="report-tracking" aria-label="レポートの更新と追跡">
    <div class="tracking-heading">
      <h3>レポートの更新</h3>
      <span>{{ tracking ? '自動追跡中' : '追跡期間終了' }}</span>
    </div>
    <dl>
      <div><dt>最終分析</dt><dd>{{ lifecycle.lastAnalyzedAt ? date(lifecycle.lastAnalyzedAt) : '未分析' }} <span v-if="lifecycle.revision">・第{{ lifecycle.revision }}版</span></dd></div>
      <div><dt>追跡期限</dt><dd>{{ date(lifecycle.trackingUntil) }}</dd></div>
      <div v-if="tracking && lifecycle.nextCheckAt"><dt>次回確認</dt><dd>{{ date(lifecycle.nextCheckAt) }}</dd></div>
    </dl>
    <p v-if="!tracking">以後はリクエスト時に再分析します。</p>
    <div class="tracking-actions">
      <button type="button" class="text-button" :disabled="!!job" @click="$emit('reanalyze')"><RefreshCw :size="17" aria-hidden="true" />{{ job ? '再分析中' : '再分析を依頼' }}</button>
      <button v-if="!tracking" type="button" class="text-button" @click="$emit('renew')">{{ TRACKING_DAYS }}日間追跡を再開</button>
      <a v-if="job" href="#/analyze" class="text-button">進行状況を見る</a>
    </div>
    <p class="sr-only" role="status">{{ updateStatus }}</p>
    <details v-if="lifecycle.history.length">
      <summary>更新履歴 <ChevronDown :size="16" aria-hidden="true" /></summary>
      <ol><li v-for="entry in [...lifecycle.history].reverse()" :key="entry.revision">第{{ entry.revision }}版 · {{ date(entry.analyzedAt) }} · {{ entry.reason === 'scheduled' ? '定期更新' : entry.reason === 'manual' ? 'リクエスト' : '初回分析' }}</li></ol>
    </details>
  </section>
</template>
<style scoped>
.report-tracking { margin: 28px 0; padding: 22px 0; border-block: 1px solid var(--line); }
.tracking-heading { display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; }
.tracking-heading > span { color: var(--muted); font-size: .875rem; }
dl { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 16px 0; }
dt { font-size: .875rem; color: var(--muted); margin-bottom: 4px; }
dd { margin: 0; font-size: .9375rem; font-variant-numeric: tabular-nums; }
p { color: var(--muted); font-size: .875rem; line-height: 1.7; }
.tracking-actions { display: flex; gap: 8px 20px; flex-wrap: wrap; }
summary { display: flex; align-items: center; gap: 8px; min-height: 44px; width: fit-content; cursor: pointer; font-size: .875rem; }
ol { margin: 8px 0 0; padding-left: 24px; font-size: .875rem; line-height: 2; }
</style>