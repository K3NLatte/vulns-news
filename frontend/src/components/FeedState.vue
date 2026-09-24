<script setup lang="ts">
import { SearchX, TriangleAlert, GitBranch, ArrowRight, RefreshCw } from '@lucide/vue'
defineProps<{ state: 'loading' | 'empty' | 'error' | 'repository'; message?: string }>()
defineEmits<{ reset: []; retry: []; example: [] }>()
</script>

<template>
  <div v-if="state === 'loading'" class="loading-state" role="status" aria-live="polite">
    <span class="sr-only">フィードを読み込んでいます。</span>
    <div v-for="row in 5" :key="row" class="skeleton-row" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
  </div>
  <div v-else class="empty-state" :role="state === 'error' ? 'alert' : 'status'">
    <TriangleAlert v-if="state === 'error'" :size="28" aria-hidden="true" />
    <GitBranch v-else-if="state === 'repository'" :size="28" aria-hidden="true" />
    <SearchX v-else :size="28" aria-hidden="true" />
    <h2>{{ state === 'error' ? 'フィードを読み込めませんでした' : state === 'repository' ? 'まずはリポジトリを指定' : '条件に合う記事がありません' }}</h2>
    <p>{{ state === 'error' ? message : state === 'repository' ? '公開リポジトリのURLを入力すると、関連性を表示する画面を試せます。' : 'キーワードを短くするか、重要度の絞り込みを解除してください。' }}</p>
    <button v-if="state === 'error'" type="button" class="secondary-button" @click="$emit('retry')"><RefreshCw :size="16" aria-hidden="true" />もう一度読み込む</button>
    <button v-else-if="state === 'repository'" type="button" class="secondary-button" @click="$emit('example')">サンプルURLで試す<ArrowRight :size="16" aria-hidden="true" /></button>
    <button v-else type="button" class="secondary-button" @click="$emit('reset')">検索条件をリセット</button>
  </div>
</template>
