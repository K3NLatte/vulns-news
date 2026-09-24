<script setup lang="ts">
import { computed, nextTick, onScopeDispose, ref, watch } from 'vue'
import { Rss, GitBranch, Info, ArrowUpRight, SlidersHorizontal, X } from '@lucide/vue'
import FeedDetail from './components/FeedDetail.vue'
import FeedList from './components/FeedList.vue'
import FeedState from './components/FeedState.vue'
import FeedToolbar from './components/FeedToolbar.vue'
import RepositoryForm from './components/RepositoryForm.vue'
import { useFeed, type PreviewState } from './composables/useFeed'
import type { FeedQuery, FeedScope, FeedSort, Severity } from './types/feed'

const scope = ref<FeedScope>('all')
const search = ref('')
const settledSearch = ref('')
const severity = ref<Severity | 'all'>('all')
const sort = ref<FeedSort>('newest')
const repositoryUrl = ref('')
const repositoryLabel = ref('')
const preview = ref<PreviewState>('ready')
const aboutOpen = ref(false)
const mobileDetail = ref(false)
let searchTimer: ReturnType<typeof setTimeout>
watch(search, value => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => { settledSearch.value = value.trim() }, 200)
})
onScopeDispose(() => clearTimeout(searchTimer))
const query = computed<FeedQuery>(() => ({ scope: scope.value, repositoryUrl: repositoryUrl.value || undefined, search: settledSearch.value, severity: severity.value, sort: sort.value }))
const enabled = computed(() => scope.value === 'all' || Boolean(repositoryUrl.value))
const { items, total, selectedId, selected, loading, error, reload } = useFeed(query, enabled, preview)
const hasFilters = computed(() => Boolean(search.value.trim()) || severity.value !== 'all')
watch([scope, search, severity, sort, preview], () => { mobileDetail.value = false })

function setRepository(url: string, label: string) {
  repositoryUrl.value = url
  repositoryLabel.value = label
  mobileDetail.value = false
}
function showExample() { setRepository('https://github.com/example/atlas-console', 'example/atlas-console') }
function resetFilters() {
  search.value = ''
  settledSearch.value = ''
  severity.value = 'all'
  preview.value = 'ready'
}
function retry() {
  if (preview.value !== 'ready') preview.value = 'ready'
  else void reload()
}
async function selectItem(id: string) {
  selectedId.value = id
  mobileDetail.value = true
  await nextTick()
  document.getElementById('detail-title')?.focus({ preventScroll: true })
  if (window.matchMedia('(max-width: 899px)').matches) {
    document.getElementById('feed-workspace')?.scrollIntoView({ block: 'start' })
  }
}
async function backToList() {
  mobileDetail.value = false
  await nextTick()
  document.getElementById(`article-${selectedId.value}`)?.focus()
}
</script>

<template>
  <a class="skip-link" href="#main-content">フィードに移動</a>
  <header class="app-header">
    <a class="brand" href="#main-content" aria-label="vulns-news フィードへ">
      <svg class="brand-mark" width="28" height="28" viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="m5 8 11 17L27 8M10 8l6 9 6-9" stroke="currentColor" stroke-width="2" /></svg>
      <span>vulns<span class="brand-divider">/</span>news</span>
    </a>
    <div class="header-actions"><span class="local-label">LOCAL MOCK</span><button class="header-help" type="button" aria-label="このモックについて" :aria-expanded="aboutOpen" aria-controls="about-panel" @click="aboutOpen = !aboutOpen"><Info :size="17" aria-hidden="true" /><span>このモックについて</span></button></div>
  </header>
  <div class="demo-banner"><span class="demo-dot" aria-hidden="true"></span><span>架空の脆弱性データを表示しています。実際の情報収集・リポジトリ解析は行いません。</span></div>
  <aside v-if="aboutOpen" id="about-panel" class="about-panel" aria-labelledby="about-title">
    <div><h2 id="about-title">画面の動きを確認するためのモックです</h2><p>検索、絞り込み、並び替え、記事詳細、リポジトリ向け表示を試せます。入力したURLは外部へ送信せず、再読み込みするとリセットされます。</p><p>ログイン・複数リポジトリの保存・記事の保存・コメント・バックエンドAPIとの接続は、今後の実装範囲です。</p></div>
    <button class="icon-button" aria-label="説明を閉じる" type="button" @click="aboutOpen = false"><X :size="18" /></button>
  </aside>
  <main id="main-content" class="main-content">
    <div class="page-heading"><div><h1>脆弱性フィード</h1><p>影響範囲を読み解き、対応の根拠を確認。</p></div><span class="dataset-date">サンプル基準日 <time datetime="2026-09-24">2026.09.24</time></span></div>
    <nav class="feed-views" aria-label="フィードの表示対象">
      <button type="button" :class="{ active: scope === 'all' }" :aria-pressed="scope === 'all'" @click="scope = 'all'"><Rss :size="17" aria-hidden="true" />すべての脆弱性</button>
      <button type="button" :class="{ active: scope === 'repository' }" :aria-pressed="scope === 'repository'" @click="scope = 'repository'"><GitBranch :size="17" aria-hidden="true" />リポジトリに関連</button>
    </nav>
    <RepositoryForm v-if="scope === 'repository'" :repository="repositoryUrl" @submit="setRepository" />
    <div v-if="scope === 'repository' && repositoryLabel" class="repository-context"><GitBranch :size="15" aria-hidden="true" /><strong>{{ repositoryLabel }}</strong><span>サンプル依存構成による表示</span></div>
    <FeedToolbar v-model:search="search" v-model:severity="severity" v-model:sort="sort" />
    <div class="results-heading">
      <p aria-live="polite" aria-atomic="true"><template v-if="loading">読み込み中</template><template v-else-if="error">読み込みエラー</template><template v-else-if="!enabled">リポジトリ未指定</template><template v-else><strong>{{ items.length }}</strong> 件<span v-if="hasFilters"> / 全{{ total }}件</span><span class="result-scope">{{ scope === 'all' ? '一般フィード' : '関連フィード' }}</span></template></p>
      <button v-if="hasFilters" class="text-button reset-filters" type="button" @click="resetFilters"><X :size="13" aria-hidden="true" />条件を解除</button>
      <details class="preview-tools"><summary><SlidersHorizontal :size="14" aria-hidden="true" />表示状態を試す</summary><div class="preview-popover"><label for="preview-state">モックの表示状態</label><select id="preview-state" v-model="preview"><option value="ready">通常</option><option value="loading">読み込み中</option><option value="empty">0件</option><option value="error">エラー</option></select><p>「通常」で元に戻ります。</p></div></details>
    </div>
    <div id="feed-workspace" class="feed-workspace" :class="{ 'is-reading': mobileDetail, 'is-single': !selected || loading || error || !enabled }">
      <section class="list-panel" aria-label="記事一覧" :aria-busy="loading">
        <FeedState v-if="!enabled" state="repository" @example="showExample" />
        <FeedState v-else-if="loading" state="loading" />
        <FeedState v-else-if="error" state="error" :message="error" @retry="retry" />
        <FeedState v-else-if="!items.length" state="empty" @reset="resetFilters" />
        <FeedList v-else :items="items" :selected-id="selectedId" :personalized="scope === 'repository'" @select="selectItem" />
      </section>
      <FeedDetail v-if="selected && !loading && !error && enabled" :key="selected.id" :item="selected" :personalized="scope === 'repository'" @back="backToList" />
    </div>
    <footer class="page-footer"><span>vulns/news · Frontend preview</span><a href="https://nvd.nist.gov/" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">実際の脆弱性情報はNVDへ<ArrowUpRight :size="13" aria-hidden="true" /><span class="sr-only">（新しいタブで開く）</span></a></footer>
  </main>
</template>
