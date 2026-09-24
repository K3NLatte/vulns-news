<script setup lang="ts">
import { nextTick, ref } from 'vue'
import { ChevronDown, Search, X } from '@lucide/vue'
import type { FeedSort, Severity } from '../types/feed'
import { severityLabels } from '../utils/presentation'

defineProps<{
  search: string
  severity: Severity | 'all'
  sort: FeedSort
  allowRelevanceSort: boolean
}>()
const emit = defineEmits<{
  'update:search': [value: string]
  'update:severity': [value: Severity | 'all']
  'update:sort': [value: FeedSort]
}>()
const severities: Severity[] = ['critical', 'high', 'medium', 'low']
const searchInput = ref<HTMLInputElement | null>(null)

async function clearSearch() {
  emit('update:search', '')
  await nextTick()
  searchInput.value?.focus()
}
</script>

<template>
  <div class="feed-toolbar">
    <div class="search-field">
      <Search :size="19" aria-hidden="true" />
      <label class="sr-only" for="feed-search">記事を検索</label>
      <input
        id="feed-search" ref="searchInput" type="search" :value="search" placeholder="製品名・キーワードで検索"
        @input="emit('update:search', ($event.target as HTMLInputElement).value)"
      />
      <button v-if="search" type="button" class="icon-button clear-search" aria-label="検索をクリア" @click="clearSearch">
        <X :size="18" aria-hidden="true" />
      </button>
    </div>
    <div class="filter-fields">
      <div class="select-field">
        <label for="severity-filter">CVSS重要度</label>
        <div class="select-control">
          <select id="severity-filter" :value="severity" @change="emit('update:severity', ($event.target as HTMLSelectElement).value as Severity | 'all')">
            <option value="all">すべて</option>
            <option v-for="value in severities" :key="value" :value="value">{{ severityLabels[value] }}</option>
          </select>
          <ChevronDown :size="18" aria-hidden="true" />
        </div>
      </div>
      <div class="select-field">
        <label for="feed-sort">並び順</label>
        <div class="select-control">
          <select id="feed-sort" :value="sort" @change="emit('update:sort', ($event.target as HTMLSelectElement).value as FeedSort)">
            <option value="newest">公開が新しい順</option>
            <option value="severity">重要度が高い順</option>
            <option v-if="allowRelevanceSort" value="relevance">関連度が高い順</option>
          </select>
          <ChevronDown :size="18" aria-hidden="true" />
        </div>
      </div>
    </div>
  </div>
</template>
