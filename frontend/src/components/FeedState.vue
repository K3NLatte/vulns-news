<script setup lang="ts">
import { RefreshCw, SearchX, TriangleAlert } from '@lucide/vue'
defineProps<{ state: 'loading' | 'error' | 'empty' | 'repository' | 'saved'; message?: string }>()
defineEmits<{ retry: []; reset: []; repositories: [] }>()
</script>

<template>
  <div v-if="state === 'loading'" class="loading-state" role="status" aria-live="polite">
    <span class="sr-only">読み込み中</span>
    <div v-for="row in 4" :key="row" class="skeleton-row" aria-hidden="true"><span></span><span></span><span></span></div>
  </div>
  <div v-else class="empty-state" :role="state === 'error' ? 'alert' : 'status'">
    <TriangleAlert v-if="state === 'error'" :size="28" aria-hidden="true" />
    <SearchX v-else :size="28" aria-hidden="true" />
    <h2>{{ state === 'error' ? '読み込めませんでした' : state === 'repository' ? 'リポジトリを追加してください' : state === 'saved' ? '保存した記事はありません' : '該当する記事がありません' }}</h2>
    <p v-if="state === 'error'">{{ message }}</p>
    <button v-if="state === 'error'" type="button" class="secondary-button" @click="$emit('retry')">
      <RefreshCw :size="18" aria-hidden="true" />再試行
    </button>
    <button v-else-if="state === 'repository'" type="button" class="secondary-button" @click="$emit('repositories')">リポジトリを追加</button>
    <button v-else-if="state === 'empty'" type="button" class="secondary-button" @click="$emit('reset')">検索条件を解除</button>
  </div>
</template>
