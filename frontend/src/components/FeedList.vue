<script setup lang="ts">
import { ChevronRight, GitBranch, Radio } from '@lucide/vue'
import type { FeedItem } from '../types/feed'
import { exploitationLabels, relevanceLabels, shortDate } from '../utils/presentation'
import SeverityBadge from './SeverityBadge.vue'
defineProps<{ items: FeedItem[]; selectedId: string | null; personalized: boolean }>()
const emit = defineEmits<{ select: [id: string] }>()
</script>

<template>
  <ol class="feed-list" aria-label="脆弱性記事">
    <li v-for="item in items" :key="item.id">
      <button :id="`article-${item.id}`" class="feed-item" :class="{ 'is-selected': selectedId === item.id }" :aria-current="selectedId === item.id ? 'true' : undefined" type="button" @click="emit('select', item.id)">
        <span class="item-topline"><SeverityBadge :severity="item.severity" :score="item.cvss" /><span class="advisory-id">{{ item.advisoryId }}</span><time :datetime="item.publishedAt">{{ shortDate(item.publishedAt) }}</time></span>
        <span class="item-title">{{ item.title }}</span>
        <span class="item-summary">{{ item.summary }}</span>
        <span class="item-bottomline">
          <span class="product-name">{{ item.product }}</span>
          <span v-if="personalized && item.relevance" class="relevance-tag"><GitBranch :size="13" aria-hidden="true" />{{ relevanceLabels[item.relevance.kind] }}</span>
          <span v-else class="exploit-label" :class="{ 'exploit-observed': item.exploitation === 'observed' }"><Radio v-if="item.exploitation === 'observed'" :size="13" aria-hidden="true" />{{ exploitationLabels[item.exploitation] }}</span>
          <ChevronRight class="item-chevron" :size="17" aria-hidden="true" />
        </span>
      </button>
    </li>
  </ol>
</template>
