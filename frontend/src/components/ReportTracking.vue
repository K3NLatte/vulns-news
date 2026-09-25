<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RefreshCw, ChevronDown } from '@lucide/vue'
import { TRACKING_DAYS, isTrackingActive } from '../services/reports'
import { dateTime } from '../utils/presentation'
import type { ReportLifecycle } from '../types/reports'
import type { InvestigationJob } from '../types/investigation'
const props = withDefaults(
  defineProps<{
    lifecycle: ReportLifecycle
    now: string
    job?: InvestigationJob
    actionMessage?: string
    pending?: boolean
    headingLevel?: 2 | 3
  }>(),
  { headingLevel: 3 },
)
const emit = defineEmits<{ reanalyze: []; renew: [] }>()
const analyzed = computed(() => props.lifecycle.revision > 0)
const tracking = computed(() => analyzed.value && isTrackingActive(props.lifecycle, props.now))
const busy = computed(
  () =>
    props.pending ||
    (props.job && props.job.kind !== 'repository' && ['queued', 'collecting', 'analyzing'].includes(props.job.status)),
)
const updateStatus = ref('')
watch(
  () => props.lifecycle.revision,
  (revision, previous) => {
    if (revision > previous) updateStatus.value = `レポートを第${revision}版に更新しました。`
  },
)
</script>
<template>
  <section class="report-tracking" aria-label="レポートの更新と追跡">
    <div class="tracking-heading">
      <component :is="`h${headingLevel}`">レポートの更新</component>
      <span>{{ !analyzed ? '未分析' : tracking ? '自動追跡中' : '追跡期間終了' }}</span>
    </div>
    <dl v-if="analyzed">
      <div>
        <dt>最終分析</dt>
        <dd>{{ dateTime(lifecycle.lastAnalyzedAt) }} ・第{{ lifecycle.revision }}版</dd>
      </div>
      <div>
        <dt>追跡期限</dt>
        <dd>{{ dateTime(lifecycle.trackingUntil) }}</dd>
      </div>
      <div v-if="tracking && lifecycle.nextCheckAt">
        <dt>次回確認</dt>
        <dd>{{ dateTime(lifecycle.nextCheckAt) }}</dd>
      </div>
    </dl>
    <p v-if="analyzed && !tracking">以後はリクエスト時に再分析します。</p>
    <div class="tracking-actions">
      <button
        type="button"
        class="text-button"
        :aria-disabled="Boolean(busy)"
        :aria-busy="Boolean(busy)"
        @click="!busy && emit('reanalyze')"
      >
        <RefreshCw :size="17" aria-hidden="true" />{{ analyzed ? '再分析を依頼' : '分析を依頼' }}
      </button>
      <button
        v-if="analyzed"
        type="button"
        class="text-button"
        :aria-disabled="tracking || pending"
        :aria-busy="pending"
        @click="!pending && !tracking && emit('renew')"
      >
        {{ TRACKING_DAYS }}日間追跡を再開
      </button>
      <a v-if="busy" href="#/analyze" class="text-button">進行状況を見る</a>
    </div>
    <p role="status" aria-live="polite">
      {{ actionMessage || (busy ? (analyzed ? '再分析中' : '分析待ち') : updateStatus) }}
    </p>
    <details v-if="analyzed && lifecycle.history.length">
      <summary>更新履歴 <ChevronDown :size="16" aria-hidden="true" /></summary>
      <ol>
        <li v-for="entry in [...lifecycle.history].reverse()" :key="entry.revision">
          第{{ entry.revision }}版 · {{ dateTime(entry.analyzedAt) }} ·
          {{ entry.reason === 'scheduled' ? '定期更新' : entry.reason === 'manual' ? 'リクエスト' : '初回分析' }}
        </li>
      </ol>
    </details>
  </section>
</template>
<style scoped>
.report-tracking {
  margin: 28px 0;
  padding: 22px 0;
  border-block: 1px solid var(--line);
}
.tracking-heading {
  display: flex;
  align-items: baseline;
  gap: 16px;
  flex-wrap: wrap;
}
.tracking-heading > span {
  color: var(--muted);
  font-size: 0.875rem;
}
dl {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(180px, 100%), 1fr));
  gap: 16px;
  margin: 16px 0;
}
dt {
  font-size: 0.875rem;
  color: var(--muted);
  margin-bottom: 4px;
}
dd {
  margin: 0;
  font-size: 0.9375rem;
  font-variant-numeric: tabular-nums;
}
p {
  color: var(--muted);
  font-size: 0.875rem;
  line-height: 1.7;
}
.tracking-actions {
  display: flex;
  gap: 8px 20px;
  flex-wrap: wrap;
}
summary {
  display: flex;
  align-items: center;
  gap: 8px;
  min-height: 44px;
  width: fit-content;
  cursor: pointer;
  font-size: 0.875rem;
}
ol {
  margin: 8px 0 0;
  padding-left: 24px;
  font-size: 0.875rem;
  line-height: 2;
}
</style>
