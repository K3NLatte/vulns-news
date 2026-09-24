<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import {
  ArrowLeft,
  ArrowUpRight,
  BookOpen,
  Bookmark,
  BookmarkCheck,
  Check,
  ChevronDown,
  Copy,
  FlaskConical,
  GitBranch,
  Maximize2,
  MessageSquare,
} from '@lucide/vue'
import type { FeedItem } from '../types/feed'
import type { FeedComment, ReviewStatus } from '../types/workspace'
import {
  confidenceLabels,
  exploitationLabels,
  fullDate,
  relevanceLabels,
  safeExternalUrl,
} from '../utils/presentation'
import ShareArticle from './ShareArticle.vue'
import ReportTracking from './ReportTracking.vue'
import type { ReportLifecycle } from '../types/reports'
import type { InvestigationJob } from '../types/investigation'
import CommentThread from './CommentThread.vue'
import SeverityBadge from './SeverityBadge.vue'

const props = withDefaults(defineProps<{
  lifecycle?: ReportLifecycle
  now?: string
  reportJob?: InvestigationJob
  item: FeedItem
  personalized: boolean
  expanded?: boolean
  fullFeatures?: boolean
  canReview?: boolean
  saved?: boolean
  comments?: FeedComment[]
  commentError?: string
  currentUserId?: string
  reviewStatus?: ReviewStatus
}>(), {
  expanded: false,
  fullFeatures: true,
  canReview: true,
  saved: false,
  comments: () => [],
  commentError: '',
  currentUserId: '',
  reviewStatus: 'unreviewed',
})

const emit = defineEmits<{
  reanalyze: []
  renew: []
  back: []
  expand: []
  comments: []
  'toggle-save': []
  'add-comment': [body: string]
  'delete-comment': [id: string]
  'update:review-status': [value: ReviewStatus]
}>()

const priorityLabels = {
  urgent: '最優先',
  high: '高',
  medium: '中',
  low: '低',
  review: '要確認',
} as const

const reviewStatuses: { value: ReviewStatus; label: string }[] = [
  { value: 'unreviewed', label: '未確認' },
  { value: 'investigating', label: '調査中' },
  { value: 'resolved', label: '対応済み' },
  { value: 'not-affected', label: '影響なし' },
]

const pending = computed(() => props.personalized && props.item.repositoryAnalysis === 'pending')
const copied = ref(false)
const copyError = ref('')
const repositoryPriority = computed(() => pending.value ? 'review' : props.item.relevance?.priority ?? 'review')
const relevanceScore = computed(() => {
  if (pending.value) return undefined
  const score = props.item.relevance?.score
  return typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 100
    ? score
    : undefined
})
const sources = computed(() => props.item.sources.map(source => ({
  ...source,
  safeUrl: safeExternalUrl(source.url),
})))

watch(() => props.item.id, () => {
  copied.value = false
  copyError.value = ''
})

async function copyId() {
  const advisoryId = props.item.advisoryId
  copyError.value = ''
  try {
    await navigator.clipboard.writeText(advisoryId)
    if (props.item.advisoryId === advisoryId) copied.value = true
  } catch {
    if (props.item.advisoryId === advisoryId) {
      copyError.value = 'コピーできませんでした。IDを選択してコピーしてください。'
    }
  }
}

function updateReviewStatus(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  const option = reviewStatuses.find(status => status.value === value)
  if (option) emit('update:review-status', option.value)
}
</script>

<template>
  <article
    class="feed-detail"
    :class="{ 'is-expanded': expanded, 'is-page': expanded }"
    aria-labelledby="detail-title"
  >
    <div class="detail-topline">
      <button
        class="text-button"
        :class="expanded ? 'detail-back' : 'mobile-back'"
        type="button"
        @click="emit('back')"
      >
        <ArrowLeft :size="18" aria-hidden="true" />
        一覧に戻る
      </button>
      <span v-if="!expanded" class="detail-label">
        <BookOpen :size="18" aria-hidden="true" />
        記事の詳細
      </span>
      <div class="detail-actions">
        <ShareArticle v-if="fullFeatures" :article-id="item.id" :title="item.title" />
        <button
          v-if="fullFeatures"
          class="text-button save-button"
          :class="{ 'is-saved': saved }"
          type="button"
          :aria-pressed="saved"
          :aria-label="saved ? '記事の保存を解除' : '記事を保存'"
          @click="emit('toggle-save')"
        >
          <BookmarkCheck v-if="saved" :size="18" aria-hidden="true" />
          <Bookmark v-else :size="18" aria-hidden="true" />
          {{ saved ? '保存済み' : '保存' }}
        </button>
        <button
          v-if="fullFeatures && !expanded"
          class="text-button comment-jump"
          type="button"
          @click="emit('comments')"
        >
          <MessageSquare :size="18" aria-hidden="true" />
          コメント（{{ comments.length }}）
        </button>
        <button
          v-if="!expanded"
          class="text-button expand-detail"
          type="button"
          @click="emit('expand')"
        >
          <Maximize2 :size="18" aria-hidden="true" />
          ページで開く
        </button>
      </div>
    </div>

    <header class="detail-header">
      <div class="detail-id-row">
        <span class="advisory-id">{{ item.advisoryId }}</span>
        <button
          class="icon-button"
          type="button"
          aria-label="記事IDをコピー"
          @click="copyId"
        >
          <Check v-if="copied" :size="18" aria-hidden="true" />
          <Copy v-else :size="18" aria-hidden="true" />
        </button>
        <span class="copy-feedback" role="status">
          {{ copied ? 'コピーしました' : '' }}
        </span>
      </div>
      <p v-if="copyError" class="input-error" role="alert">{{ copyError }}</p>

      <h2 id="detail-title" tabindex="-1">{{ item.title }}</h2>
      <div class="detail-meta">
        <span class="detail-cvss">
          <span class="cvss-label">CVSS</span>
          <span v-if="item.assessment === 'unverified'" class="severity-badge">未評価</span>
          <SeverityBadge v-else :severity="item.severity" :score="item.cvss" />
          <span v-if="item.cvss === null">未評価</span>
        </span>
        <span>{{ item.assessment === 'unverified' ? '悪用情報 未確認' : exploitationLabels[item.exploitation] }}</span>
      </div>
    </header>
    <div class="detail-content" :tabindex="expanded ? undefined : 0" role="region" aria-label="記事の本文">
      <p v-if="pending" class="pending-analysis-note"><strong>リポジトリとの関連性は未確定です。</strong>影響の判断に必要な情報が不足しています。</p>
      <p class="detail-summary">{{ item.summary }}</p>
      <ReportTracking v-if="fullFeatures && lifecycle && now" :lifecycle="lifecycle" :now="now" :job="reportJob" @reanalyze="emit('reanalyze')" @renew="emit('renew')" />

      <dl class="facts-grid">
        <div>
          <dt>対象製品</dt>
          <dd>{{ item.product }}</dd>
        </div>
        <div>
          <dt>影響を受けるバージョン</dt>
          <dd class="version-text">{{ item.affectedVersions }}</dd>
        </div>
        <div>
          <dt>修正バージョン</dt>
          <dd class="version-text">{{ item.fixedVersion }}</dd>
        </div>
        <div>
          <dt>公開日</dt>
          <dd><time :datetime="item.publishedAt">{{ fullDate(item.publishedAt) }}</time></dd>
        </div>
      </dl>

      <section
        v-if="personalized && item.relevance"
        class="relevance-section"
        aria-labelledby="relevance-heading"
      >
        <div class="section-heading">
          <h3 id="relevance-heading">
            <GitBranch :size="18" aria-hidden="true" />
            リポジトリへの影響
          </h3>
          <span class="priority-badge" :class="'priority-' + repositoryPriority">
            優先度：{{ priorityLabels[repositoryPriority] }}
          </span>
        </div>
        <dl class="repository-impact-facts">
          <div>
            <dt>依存関係</dt>
            <dd>{{ relevanceLabels[item.relevance.kind] }}</dd>
          </div>
          <div>
            <dt>導入バージョン</dt>
            <dd><code>{{ item.relevance.packageName }}@{{ item.relevance.installedVersion }}</code></dd>
          </div>
          <div v-if="relevanceScore !== undefined">
            <dt>関連度</dt>
            <dd>{{ relevanceScore }} / 100</dd>
          </div>
        </dl>
        <p class="impact-reason">{{ item.relevance.reason }}</p>
      </section>

      <section
        v-if="fullFeatures && personalized && canReview"
        class="detail-section triage-section"
        aria-labelledby="review-heading"
      >
        <h3 id="review-heading">対応状況</h3>
        <div class="review-control">
          <label for="article-review-status">このリポジトリでの対応</label>
          <span class="select-control">
            <select
              id="article-review-status"
              :value="reviewStatus"
              @change="updateReviewStatus"
            >
              <option v-for="status in reviewStatuses" :key="status.value" :value="status.value">
                {{ status.label }}
              </option>
            </select>
            <ChevronDown :size="18" aria-hidden="true" />
          </span>
        </div>
      </section>

      <section v-if="!pending" class="detail-section" aria-labelledby="remediation-heading">
        <h3 id="remediation-heading">対応の確認ポイント</h3>
        <ol class="remediation-list">
          <li v-for="step in item.remediation" :key="step">{{ step }}</li>
        </ol>
      </section>

      <section v-if="!pending" class="analysis-section" aria-labelledby="analysis-heading">
        <div class="section-heading">
          <h3 id="analysis-heading">
            <FlaskConical :size="18" aria-hidden="true" />
            分析
          </h3>
          <span class="confidence-label">確度：{{ confidenceLabels[item.analysis.confidence] }}</span>
        </div>
        <p>{{ item.analysis.summary }}</p>
        <details>
          <summary>根拠を読む</summary>
          <p>{{ item.analysis.evidence }}</p>
        </details>
      </section>

      <details v-if="fullFeatures && !pending && item.proofOfConcept" class="detail-section poc-section">
        <summary>PoC</summary>
        <div class="poc-content">
          <h3 v-if="item.proofOfConcept.conditions.length">確認条件</h3>
          <ul v-if="item.proofOfConcept.conditions.length" class="poc-conditions">
            <li v-for="condition in item.proofOfConcept.conditions" :key="condition">
              {{ condition }}
            </li>
          </ul>
          <span class="poc-language">{{ item.proofOfConcept.language }}</span>
          <pre><code>{{ item.proofOfConcept.code }}</code></pre>
        </div>
      </details>

      <section class="detail-section reference-section" aria-labelledby="reference-heading">
        <h3 id="reference-heading">参照情報</h3>
        <ul>
          <li v-for="source in sources" :key="source.url">
            <span class="source-kind">{{ source.kind === 'vendor' ? '提供元' : '技術資料' }}</span>
            <a
              v-if="source.safeUrl"
              :href="source.safeUrl"
              target="_blank"
              rel="noopener noreferrer"
              referrerpolicy="no-referrer"
            >
              {{ source.name }}
              <ArrowUpRight :size="17" aria-hidden="true" />
              <span class="sr-only">（新しいタブで開く）</span>
            </a>
            <span v-else>{{ source.name }}</span>
          </li>
        </ul>
      </section>

      <p class="detail-footer">
        更新日：<time :datetime="item.updatedAt">{{ fullDate(item.updatedAt) }}</time>
      </p>

      <CommentThread
        v-if="expanded && fullFeatures"
        :key="item.id"
        :comments="comments"
        :submission-error="commentError"
        :current-user-id="currentUserId"
        @add="emit('add-comment', $event)"
        @remove="emit('delete-comment', $event)"
      />
    </div>
  </article>
</template>