<script setup lang="ts">
import { computed } from 'vue'
import { CircleAlert, CircleCheck, Clock3, LoaderCircle, RotateCw } from '@lucide/vue'
import type { AnalysisSnapshot, AnalysisStage } from '../types/analysis'

const props = defineProps<{ snapshot: AnalysisSnapshot }>()
const emit = defineEmits<{ retry: [] }>()

const titles: Record<AnalysisStage, string> = {
  queued: '解析待ち',
  profiling: 'リポジトリの構成を確認中',
  matching: '脆弱性情報と照合中',
  screening: '関連性を確認中',
  analyzing: '関連する記事を分析中',
  completed: '解析完了',
  failed: '解析を完了できませんでした',
}
const countFormat = new Intl.NumberFormat('ja-JP')

function knownCount(value: number | undefined): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined
}

const counts = computed(() => ({
  processed: knownCount(props.snapshot.processed),
  total: knownCount(props.snapshot.total),
  confirmed: knownCount(props.snapshot.confirmedCount),
  pending: knownCount(props.snapshot.pendingCount),
}))
const hasAvailableResults = computed(() => (
  props.snapshot.hasAvailableResults === true
  || (counts.value.confirmed ?? 0) > 0
  || (counts.value.pending ?? 0) > 0
))
const isBusy = computed(() => (
  props.snapshot.stage !== 'completed' && props.snapshot.stage !== 'failed'
))
const icon = computed(() => {
  if (props.snapshot.stage === 'completed') return CircleCheck
  if (props.snapshot.stage === 'failed') return CircleAlert
  if (props.snapshot.stage === 'queued') return Clock3
  return LoaderCircle
})
const progress = computed(() => {
  const { processed, total } = counts.value
  if (processed !== undefined && total !== undefined && processed <= total) {
    return '処理済み ' + countFormat.format(processed) + ' / ' + countFormat.format(total) + '件'
  }
  if (processed !== undefined) return '処理済み ' + countFormat.format(processed) + '件'
  if (total !== undefined) return '対象 ' + countFormat.format(total) + '件'
  return ''
})
const message = computed(() => {
  if (props.snapshot.stage === 'completed') return ''
  if (props.snapshot.stage === 'failed') {
    const error = props.snapshot.errorMessage?.trim() ?? ''
    const available = hasAvailableResults.value ? '表示済みの記事は引き続き閲覧できます。' : ''
    return [error, available].filter(Boolean).join(' ')
  }
  return hasAvailableResults.value
    ? '確認できた記事から表示しています。'
    : '解析中もほかのフィードを閲覧できます。'
})
</script>

<template>
  <section
    class="analysis-status"
    :class="['is-' + snapshot.stage, { 'is-active': isBusy }]"
    aria-label="リポジトリの解析状況"
  >
    <component
      :is="icon"
      class="analysis-status-icon"
      :size="20"
      aria-hidden="true"
    />
    <div
      class="analysis-status-body"
      role="status"
      aria-live="polite"
      aria-atomic="true"
    >
      <div class="analysis-status-heading">
        <p class="analysis-status-title">{{ titles[snapshot.stage] }}</p>
        <span v-if="progress" class="analysis-status-progress">{{ progress }}</span>
      </div>
      <p v-if="message" class="analysis-status-message">{{ message }}</p>
      <dl
        v-if="counts.confirmed !== undefined || counts.pending !== undefined"
        class="analysis-status-counts"
      >
        <div v-if="counts.confirmed !== undefined">
          <dt>分析済み</dt>
          <dd>{{ countFormat.format(counts.confirmed) }}件</dd>
        </div>
        <div v-if="counts.pending !== undefined">
          <dt>未確定</dt>
          <dd>{{ countFormat.format(counts.pending) }}件</dd>
        </div>
      </dl>
    </div>
    <button
      v-if="snapshot.stage === 'failed'"
      class="secondary-button analysis-status-retry"
      type="button"
      @click="emit('retry')"
    >
      <RotateCw :size="17" aria-hidden="true" />
      再試行
    </button>
  </section>
</template>