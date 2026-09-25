<script setup lang="ts">
import { ArrowUpRight, Bookmark, GitBranch } from '@lucide/vue'
import type { FeedItem } from '../types/feed'
import { exploitationLabels, relevanceLabels, shortDate } from '../utils/presentation'
import { articlePath } from '../composables/useNavigation'
import SeverityBadge from './SeverityBadge.vue'

withDefaults(
  defineProps<{
    items: FeedItem[]
    selectedId: string | null
    personalized: boolean
    repositoryUrl?: string
    fullFeatures?: boolean
    savedIds?: string[]
    splitView?: boolean
  }>(),
  { fullFeatures: true, savedIds: () => [], splitView: true },
)
const emit = defineEmits<{ select: [id: string]; 'toggle-save': [id: string]; 'focus-detail': [] }>()
const priorityLabels = { urgent: '最優先', high: '高', medium: '中', low: '低', review: '要確認' }
</script>

<template>
  <ol class="feed-list" aria-label="脆弱性記事">
    <li v-for="item in items" :key="item.id" :class="{ 'is-selected': splitView && selectedId === item.id }">
      <button
        :id="'article-' + item.id"
        class="feed-item"
        type="button"
        :aria-current="splitView && selectedId === item.id ? 'true' : undefined"
        :aria-labelledby="`title-${item.id} id-${item.id}`"
        @click="emit('select', item.id)"
      >
        <span class="item-topline">
          <span v-if="item.assessment === 'unverified'" class="list-cvss"
            >CVSS <span class="severity-badge">未評価</span></span
          >
          <span v-else class="list-cvss"
            ><span>CVSS</span><SeverityBadge :severity="item.severity" :score="item.cvss"
          /></span>
          <span :id="`id-${item.id}`" class="advisory-id">{{ item.advisoryId }}</span>
          <span
            v-if="personalized && item.repositoryAnalysis"
            class="analysis-badge"
            :class="'analysis-' + item.repositoryAnalysis"
            >{{ item.repositoryAnalysis === 'pending' ? '未確定' : '分析済み' }}</span
          >
          <time v-if="item.publishedAt" :datetime="item.publishedAt">{{ shortDate(item.publishedAt) }}</time
          ><span v-else class="item-date">公開日 未確認</span>
        </span>
        <span :id="`title-${item.id}`" class="item-title">{{ item.title }}</span>
        <span class="item-summary">{{ item.summary }}</span>
        <span class="item-bottomline">
          <span class="product-name">{{ item.product ?? '対象製品 未確認' }}</span>
          <span v-if="personalized && item.repositoryAnalysis === 'analyzed' && item.relevance" class="relevance-tag">
            <GitBranch :size="15" aria-hidden="true" />{{ relevanceLabels[item.relevance.kind] }}
          </span>
          <span v-else>{{
            item.assessment === 'unverified' ? '悪用情報 未確認' : exploitationLabels[item.exploitation]
          }}</span>
        </span>
        <span v-if="personalized" class="item-priority">
          <span
            class="priority-badge"
            :class="
              'priority-' +
              (item.repositoryAnalysis !== 'analyzed' || !item.relevance ? 'review' : item.relevance.priority)
            "
          >
            対応優先度
            {{
              item.repositoryAnalysis !== 'analyzed' || !item.relevance
                ? '未確定'
                : priorityLabels[item.relevance.priority]
            }}
          </span>
          <span
            >関連度
            {{
              item.repositoryAnalysis !== 'analyzed' || !item.relevance ? '未確定' : (item.relevance.score ?? '未評価')
            }}</span
          >
        </span>
      </button>
      <div class="item-actions">
        <button
          v-if="fullFeatures"
          class="text-button save-button"
          type="button"
          :aria-label="'保存：' + item.advisoryId"
          :aria-pressed="savedIds.includes(item.id)"
          @click="emit('toggle-save', item.id)"
        >
          <Bookmark :size="17" :fill="savedIds.includes(item.id) ? 'currentColor' : 'none'" aria-hidden="true" />
          保存
        </button>
        <button
          v-if="splitView && selectedId === item.id"
          class="text-button"
          type="button"
          @click="emit('focus-detail')"
        >
          詳細を読む
        </button>
        <a
          class="text-button article-page-link"
          :href="articlePath(item.id, personalized ? repositoryUrl : undefined)"
          :aria-label="'ページで開く：' + item.advisoryId"
        >
          ページで開く<ArrowUpRight :size="16" aria-hidden="true" />
        </a>
      </div>
    </li>
  </ol>
</template>
