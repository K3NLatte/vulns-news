<script setup lang="ts">
import { ArrowLeft, ArrowUpRight, GitBranch, FlaskConical, BookOpen, Check, Copy } from '@lucide/vue'
import { ref, watch } from 'vue'
import type { FeedItem } from '../types/feed'
import { confidenceLabels, exploitationLabels, fullDate, relevanceLabels, safeExternalUrl } from '../utils/presentation'
import SeverityBadge from './SeverityBadge.vue'
const props = defineProps<{ item: FeedItem; personalized: boolean }>()
defineEmits<{ back: [] }>()
const copied = ref(false)
const copyError = ref('')
watch(() => props.item.id, () => { copied.value = false; copyError.value = '' })
async function copyId() {
  try {
    await navigator.clipboard.writeText(props.item.advisoryId)
    copied.value = true
    copyError.value = ''
  } catch { copyError.value = 'コピーできませんでした。IDを選択してコピーしてください。' }
}
</script>

<template>
  <article class="feed-detail" aria-labelledby="detail-title">
    <div class="detail-topline">
      <button class="text-button mobile-back" type="button" @click="$emit('back')"><ArrowLeft :size="17" aria-hidden="true" />一覧に戻る</button>
      <span class="detail-label"><BookOpen :size="16" aria-hidden="true" />記事の詳細</span>
      <span class="sample-label">架空の記事</span>
    </div>
    <div class="detail-content">
      <div class="detail-id-row"><span class="advisory-id">{{ item.advisoryId }}</span><button class="icon-button" type="button" :aria-label="copied ? 'IDをコピーしました' : '記事IDをコピー'" @click="copyId"><Check v-if="copied" :size="15" /><Copy v-else :size="15" /></button><span class="copy-feedback" role="status">{{ copied ? 'コピーしました' : '' }}</span></div>
      <p v-if="copyError" class="input-error" role="alert">{{ copyError }}</p>
      <h2 id="detail-title" tabindex="-1">{{ item.title }}</h2>
      <div class="detail-meta"><SeverityBadge :severity="item.severity" :score="item.cvss" /><span>{{ exploitationLabels[item.exploitation] }}</span></div>
      <p class="detail-summary">{{ item.summary }}</p>
      <dl class="facts-grid">
        <div><dt>対象製品</dt><dd>{{ item.product }}</dd></div>
        <div><dt>影響を受けるバージョン</dt><dd class="version-text">{{ item.affectedVersions }}</dd></div>
        <div><dt>修正バージョン</dt><dd class="version-text">{{ item.fixedVersion }}</dd></div>
        <div><dt>公開日</dt><dd><time :datetime="item.publishedAt">{{ fullDate(item.publishedAt) }}</time></dd></div>
      </dl>
      <section v-if="personalized && item.relevance" class="relevance-section" aria-labelledby="relevance-heading">
        <h3 id="relevance-heading"><GitBranch :size="17" aria-hidden="true" />リポジトリとの関連</h3>
        <p><span class="relevance-tag">{{ relevanceLabels[item.relevance.kind] }}</span><code>{{ item.relevance.packageName }}@{{ item.relevance.installedVersion }}</code></p>
        <p>{{ item.relevance.reason }}</p>
        <p class="section-note">サンプル依存構成での例です。入力URLの実際の解析結果ではありません。</p>
      </section>
      <section class="detail-section" aria-labelledby="remediation-heading">
        <h3 id="remediation-heading">対応の確認ポイント</h3>
        <ol class="remediation-list"><li v-for="step in item.remediation" :key="step">{{ step }}</li></ol>
      </section>
      <section class="analysis-section" aria-labelledby="analysis-heading">
        <div class="section-heading"><h3 id="analysis-heading"><FlaskConical :size="17" aria-hidden="true" />AI分析のサンプル</h3><span class="confidence-label">確度：{{ confidenceLabels[item.analysis.confidence] }}（想定）</span></div>
        <p>{{ item.analysis.summary }}</p>
        <details><summary>推定の根拠を読む</summary><p>{{ item.analysis.evidence }}</p></details>
        <p class="section-note">LLMは接続していません。実際の判断には一次情報と利用環境の確認が必要です。</p>
      </section>
      <section class="detail-section reference-section" aria-labelledby="reference-heading">
        <h3 id="reference-heading">関連する一般資料</h3>
        <p class="section-note">脆弱性の種類を理解するための資料です。この記事の実在性を示す出典ではありません。</p>
        <ul><li v-for="source in item.sources" :key="source.url"><a v-if="safeExternalUrl(source.url)" :href="safeExternalUrl(source.url)" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">{{ source.name }}<ArrowUpRight :size="16" aria-hidden="true" /><span class="sr-only">（新しいタブで開く）</span></a><span v-else>{{ source.name }}</span></li></ul>
      </section>
      <p class="detail-footer">サンプル更新日：{{ fullDate(item.updatedAt) }} · PoCの実行機能はありません。</p>
    </div>
  </article>
</template>
