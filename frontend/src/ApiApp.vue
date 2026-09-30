<script setup lang="ts">
import { computed, nextTick, onScopeDispose, ref, watch } from 'vue'
import { X } from '@lucide/vue'
import AppHeader from './components/AppHeader.vue'
import AnalysisStatus from './components/AnalysisStatus.vue'
import FeedDetail from './components/FeedDetail.vue'
import FeedList from './components/FeedList.vue'
import FeedState from './components/FeedState.vue'
import FeedToolbar from './components/FeedToolbar.vue'
import RepositoryForm from './components/RepositoryForm.vue'
import { useFeed } from './composables/useFeed'
import { useFeedDetail } from './composables/useFeedDetail'
import { useFeedPanes } from './composables/useFeedPanes'
import { articlePath, useNavigation } from './composables/useNavigation'
import { filterFeedItems, parseRepositoryUrl } from './services/feed'
import { createFeedApi, type DetailTarget, type SavedAnalysis } from './services/feedApi'
import type { AnalysisSnapshot } from './types/analysis'
import type { FeedQuery, FeedSort, Severity } from './types/feed'

const { route, navigate } = useNavigation()
const apiJob = ref<AnalysisSnapshot | null>(null)
const api = createFeedApi((url, job) => { if (url === repositoryUrl.value) apiJob.value = job })
const activeStorageKey = 'vulns-news:api-active-repository:v1'
function readActiveRepository() {
  try {
    const parsed = parseRepositoryUrl(sessionStorage.getItem(activeStorageKey))
    return parsed.ok && api.hasRepository(parsed.url) ? parsed.url : ''
  } catch { return '' }
}
const initialRepository = route.value.page === 'article' ? route.value.repositoryUrl : undefined
const activeRepository = ref(initialRepository && api.hasRepository(initialRepository) ? initialRepository : readActiveRepository())
watch(activeRepository, url => {
  try { sessionStorage.setItem(activeStorageKey, url) } catch { /* 保存不可でも、このタブでの閲覧は継続する。 */ }
}, { immediate: true })
const articlePage = computed(() => route.value.page === 'article')
const listPage = computed(() => route.value.page === 'feed' || route.value.page === 'repositories')
const repositoryUrl = computed(() => route.value.page === 'article'
  ? route.value.repositoryUrl ?? '' : route.value.page === 'repositories' ? activeRepository.value : '')
const personalized = computed(() => Boolean(repositoryUrl.value))
const registrationBusy = ref(false)
const registrationError = ref('')
const registrationVersion = ref(0)
const savedAnalyses = ref<SavedAnalysis[]>([])
const catalogLoading = ref(true)
const catalogError = ref('')
const readOnly = ref(true)
const catalogController = new AbortController()
let registrationController: AbortController | undefined
const needsRegistration = computed(() => {
  void registrationVersion.value
  return personalized.value && !api.hasRepository(repositoryUrl.value)
})
watch(repositoryUrl, () => { apiJob.value = null }, { flush: 'sync' })

const search = ref('')
const settledSearch = ref('')
const severity = ref<Severity | 'all'>('all')
const sort = ref<FeedSort>('newest')
const analysisFilter = ref<'all' | 'analyzed' | 'pending'>('all')
let searchTimer: ReturnType<typeof setTimeout>
watch(search, value => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => { settledSearch.value = value.trim() }, 200)
})
watch(personalized, value => { if (!value && sort.value === 'relevance') sort.value = 'newest' })

// 検索・並び替えでは再取得せず、同じ取得結果を絞り込む。
const listScope = ref<'all' | 'repository'>(route.value.page === 'repositories' ? 'repository' : 'all')
const acquisitionQuery = computed<FeedQuery>(() => ({
  scope: listScope.value, repositoryUrl: listScope.value === 'repository' ? activeRepository.value || undefined : undefined,
  search: '', severity: 'all', sort: 'newest',
}))
const enabled = computed(() => !catalogLoading.value && listPage.value && (listScope.value === 'all' || Boolean(activeRepository.value)))
const { items, total, scanStatus, repositoryCommit, selectedId, loading, error, reload } = useFeed(acquisitionQuery, enabled, ref('ready'), api.getFeed)
if (route.value.page === 'article') selectedId.value = route.value.articleId
const filteredItems = computed(() => filterFeedItems(items.value, {
  ...acquisitionQuery.value, search: settledSearch.value, severity: severity.value, sort: sort.value,
}))
const analyzedCount = computed(() => filteredItems.value.filter(item => item.repositoryAnalysis === 'analyzed' && item.assessment !== 'unverified').length)
const pendingCount = computed(() => filteredItems.value.length - analyzedCount.value)
const visibleItems = computed(() => filteredItems.value.filter(item => {
  if (!personalized.value || analysisFilter.value === 'all') return true
  const analyzed = item.repositoryAnalysis === 'analyzed' && item.assessment !== 'unverified'
  return analysisFilter.value === 'analyzed' ? analyzed : !analyzed
}))
const selectedSummary = computed(() => visibleItems.value.find(item => item.id === selectedId.value) ?? visibleItems.value[0] ?? null)
const hasFilters = computed(() => Boolean(search.value.trim()) || severity.value !== 'all' || analysisFilter.value !== 'all')
const workspaceElement = ref<HTMLElement | null>(null)
const controlsElement = ref<HTMLElement | null>(null)
const { splitView, paneStyle, fullPaneScroll } = useFeedPanes(workspaceElement, controlsElement, listPage)
const detailTarget = computed<DetailTarget | null>(() => {
  if (catalogLoading.value || needsRegistration.value) return null
  const id = route.value.page === 'article' ? route.value.articleId : splitView.value ? selectedSummary.value?.id : undefined
  return id ? { id, repositoryUrl: repositoryUrl.value || undefined } : null
})
const { item: selected, loading: detailLoading, error: detailError, reload: reloadDetail } = useFeedDetail(detailTarget, api.getDetail)
watch(selectedSummary, (current, previous) => {
  // 同じ記事の解析結果が更新された場合は、詳細も最新の状態に揃える。
  if (listPage.value && current && previous && current.id === previous.id && detailTarget.value?.id === current.id
    && (current.updatedAt !== previous.updatedAt || current.repositoryAnalysis !== previous.repositoryAnalysis)) void reloadDetail()
})
const detailKey = () => JSON.stringify([detailTarget.value?.id, detailTarget.value?.repositoryUrl])
let requestedDetailFocus: { key: string; origin: Element | null } | null = null
function requestDetailFocus() {
  requestedDetailFocus = { key: detailKey(), origin: document.activeElement }
}
watch(detailKey, key => {
  if (requestedDetailFocus?.key !== key) requestedDetailFocus = null
}, { flush: 'sync' })
watch(detailLoading, async busy => {
  if (busy) return
  const requested = requestedDetailFocus
  requestedDetailFocus = null
  if (detailError.value || !selected.value) return
  await nextTick()
  // 選択後に別の入力へ移った場合や対象が変わった場合は、フォーカスを奪わない。
  const keepsSelectionFocus = requested && requested.key === detailKey()
    && (document.activeElement === requested.origin
      || (requested.origin && !requested.origin.isConnected && document.activeElement === document.body))
  if (!articlePage.value && !keepsSelectionFocus) return
  document.querySelector('.detail-content')?.scrollTo({ top: 0 })
  document.getElementById('detail-title')?.focus({ preventScroll: true })
})
watch([route, selected], () => {
  document.title = (articlePage.value ? selected.value?.advisoryId ?? '記事' : personalized.value ? 'リポジトリに関連' : '脆弱性フィード') + ' | vulns-news'
}, { immediate: true })

let previousList = route.value.page === 'article' && route.value.repositoryUrl ? '#/repositories' : '#/feed'
let previousScroll = 0
let restoringList: string | null = null
async function restoreListPosition() {
  const target = restoringList
  if (!target || !listPage.value || '#/' + route.value.page !== target || (loading.value && !items.value.length)) return
  await nextTick()
  await nextTick()
  if (restoringList !== target || '#/' + route.value.page !== target) return
  window.scrollTo({ top: previousScroll })
  document.getElementById('article-' + selectedSummary.value?.id)?.focus({ preventScroll: true })
  restoringList = null
}
watch([loading, items], restoreListPosition, { flush: 'post' })
watch(route, async (next, previous) => {
  registrationController?.abort()
  registrationBusy.value = false
  registrationError.value = ''
  if (next.page === 'saved' || next.page === 'settings' || next.page === 'analyze') { navigate('#/feed'); return }
  if (next.page === 'repositories' || next.page === 'feed') listScope.value = next.page === 'repositories' ? 'repository' : 'all'
  if (next.page === 'article') {
    selectedId.value = next.articleId
    if (next.repositoryUrl && api.hasRepository(next.repositoryUrl)) activeRepository.value = next.repositoryUrl
  }
  if (next.page === 'article' && previous.page !== 'article') {
    previousList = '#/' + previous.page
    previousScroll = window.scrollY
  }
  await nextTick()
  // 画面幅に応じたペイン配置の再描画後に、スクロールを復元する。
  await nextTick()
  if (route.value !== next) return
  if (previous.page === 'article' && '#/' + next.page === previousList) {
    restoringList = previousList
    void restoreListPosition()
  } else {
    restoringList = null
    window.scrollTo({ top: 0 })
    if (next.page === 'article') {
      if (!detailLoading.value) document.getElementById('detail-title')?.focus({ preventScroll: true })
    } else document.getElementById('feed-title')?.focus({ preventScroll: true })
  }
})
if (!listPage.value && !articlePage.value) navigate('#/feed')

async function loadSavedAnalyses() {
  catalogLoading.value = true
  catalogError.value = ''
  try {
    const catalog = await api.listSavedAnalyses(catalogController.signal)
    savedAnalyses.value = catalog.items
    readOnly.value = catalog.readOnly
    registrationVersion.value++
    if (initialRepository && api.hasRepository(initialRepository)) activeRepository.value = initialRepository
  } catch (cause) {
    if (!catalogController.signal.aborted) catalogError.value = cause instanceof Error ? cause.message : '保存済み解析を取得できませんでした。'
  } finally { catalogLoading.value = false }
}
function openSavedAnalysis(repositoryID: string) {
  const item = api.selectSavedAnalysis(repositoryID)
  activeRepository.value = item.url
  registrationVersion.value++
  resetFilters()
  navigate('#/repositories')
  if (route.value.page === 'repositories') void reload()
}
void loadSavedAnalyses()

async function setRepository(url: string) {
  if (registrationBusy.value) return
  registrationController?.abort()
  const controller = new AbortController()
  registrationController = controller
  registrationBusy.value = true
  registrationError.value = ''
  try {
    const registered = await api.registerRepository(url, controller.signal)
    if (controller.signal.aborted) return
    const sameRepository = activeRepository.value === registered.url
    activeRepository.value = registered.url
    registrationVersion.value++
    analysisFilter.value = 'all'
    if (route.value.page === 'article' && registered.url !== route.value.repositoryUrl) {
      navigate(articlePath(route.value.articleId, registered.url))
    }
    if (!articlePage.value && sameRepository) void reload()
  } catch (cause) {
    if (!controller.signal.aborted) registrationError.value = cause instanceof Error ? cause.message : 'リポジトリを読み込めませんでした。'
  } finally { if (!controller.signal.aborted) registrationBusy.value = false }
}
function resetFilters() { search.value = ''; settledSearch.value = ''; severity.value = 'all'; analysisFilter.value = 'all' }
function focusMain() { document.getElementById('main-content')?.focus() }

function selectItem(id: string) {
  const unchanged = selected.value?.id === id
  selectedId.value = id
  if (!splitView.value) { navigate(articlePath(id, repositoryUrl.value || undefined)); return }
  if (unchanged) {
    requestedDetailFocus = null
    document.getElementById('detail-title')?.focus({ preventScroll: true })
  } else requestDetailFocus()
}
function retryDetail() { requestDetailFocus(); void reloadDetail() }
function expandArticle() { if (selected.value) navigate(articlePath(selected.value.id, repositoryUrl.value || undefined)) }
onScopeDispose(() => { clearTimeout(searchTimer); registrationController?.abort(); catalogController.abort() })
</script>

<template>
  <a class="skip-link" href="#main-content" @click.prevent="focusMain">本文に移動</a>
  <AppHeader :user="null" :full-features="false" :page="route.page" :saved-count="0" />
  <main id="main-content" class="main-content" :class="{ 'is-feed': listPage }" tabindex="-1">
    <div v-if="listPage" ref="controlsElement" class="feed-controls">
      <div class="feed-heading-row">
        <div class="page-heading"><h1 id="feed-title" tabindex="-1">脆弱性フィード</h1></div>
        <nav class="feed-views" aria-label="フィードの表示対象">
          <a href="#/feed" :aria-current="route.page === 'feed' ? 'page' : undefined">すべて</a>
          <a href="#/repositories" :aria-current="route.page === 'repositories' ? 'page' : undefined">リポジトリに関連</a>
        </nav>
      </div>
      <section aria-label="保存済み解析" class="saved-analyses">
        <h2>保存済み解析結果</h2>
        <p v-if="catalogLoading" role="status">保存済み解析を読み込み中…</p>
        <p v-else-if="catalogError" role="alert">{{ catalogError }} <button type="button" @click="loadSavedAnalyses">再取得</button></p>
        <template v-else>
          <p>{{ readOnly ? '読み取り専用：保存済みの結果を閲覧します。新規スキャン・LLM実行は行いません。' : '保存済みの結果を閲覧します。結果を開く操作では新規スキャンを開始しません。' }}</p>
          <p v-if="!savedAnalyses.length">保存済み解析はありません。対応する analysis-scan-state.json と analysis-results.json を import CLI で取り込んでから「再取得」を押してください。</p>
          <details v-else :open="!personalized">
            <summary>解析結果を選択（{{ savedAnalyses.length }}件）</summary>
            <ul>
              <li v-for="saved in savedAnalyses" :key="saved.job.repository_id">
                <button type="button" @click="openSavedAnalysis(saved.job.repository_id)">{{ saved.url.replace('https://github.com/', '') }} — 結果を開く</button>
                <span> {{ saved.itemCount }}件 · 分析済み {{ saved.job.confirmedCount ?? 0 }} · 未確定 {{ saved.job.pendingCount ?? 0 }} · {{ saved.scanStatus === 'incomplete' ? 'カバレッジ不完全' : 'スキャン範囲の処理完了' }}</span>
                <p>ref: {{ saved.ref || 'HEAD' }} · commit: <code>{{ saved.commit }}</code> · {{ saved.updatedAt }}</p>
              </li>
            </ul>
          </details>
          <button type="button" class="text-button" @click="loadSavedAnalyses">再取得</button>
        </template>
      </section>
      <template v-if="route.page === 'repositories'">
        <p v-if="activeRepository">表示中：{{ activeRepository }}</p>
        <details v-if="!readOnly"><summary>新規スキャン（公開URLを登録）</summary>
        <RepositoryForm :repository="activeRepository" :busy="registrationBusy" @submit="setRepository" />
        </details>
        <p v-if="registrationError" class="input-error" role="alert">{{ registrationError }}</p>
        <AnalysisStatus v-if="apiJob" :snapshot="apiJob" :allow-retry="false" />
      </template>
      <p v-if="!personalized">保存済みリポジトリの解析結果を表示しています。全脆弱性の網羅一覧ではありません。</p>
      <p v-if="repositoryCommit">対象コミット: <code>{{ repositoryCommit }}</code></p>
      <p v-if="scanStatus === 'incomplete'" role="status">スキャン範囲に未確認の項目があります。解析完了はリポジトリ全体の安全性を保証しません。</p>
      <FeedToolbar v-model:search="search" v-model:severity="severity" v-model:sort="sort" :allow-relevance-sort="personalized" />
      <div class="results-heading">
        <div v-if="personalized && items.length" class="analysis-filters" role="group" aria-label="解析結果の絞り込み">
          <button type="button" :aria-pressed="analysisFilter === 'all'" @click="analysisFilter = 'all'">すべて <span>{{ filteredItems.length }}</span></button>
          <button type="button" :aria-pressed="analysisFilter === 'analyzed'" @click="analysisFilter = 'analyzed'">分析済み <span>{{ analyzedCount }}</span></button>
          <button type="button" :aria-pressed="analysisFilter === 'pending'" @click="analysisFilter = 'pending'">未確定 <span>{{ pendingCount }}</span></button>
        </div>
        <p v-else aria-live="polite" aria-atomic="true">{{ loading && !items.length ? '読み込み中' : !enabled ? 'リポジトリ未指定' : `${visibleItems.length} 件` }}</p>
        <button v-if="hasFilters" class="text-button" type="button" @click="resetFilters"><X :size="16" aria-hidden="true" />条件を解除</button>
      </div>
      <p v-if="total > items.length" role="status">取得した {{ items.length }} 件を表示しています（全 {{ total }} 件）。検索・絞り込みは取得済みの記事が対象です。</p>
      <div v-if="error && items.length" class="storage-error" role="alert">{{ error }} <button type="button" class="text-button" @click="reload">再試行</button></div>
    </div>
    <div v-if="articlePage && needsRegistration" class="empty-state">
      <h1>{{ catalogLoading ? '保存済み解析を読み込み中' : 'このリポジトリの保存済み解析が見つかりません' }}</h1>
      <RepositoryForm v-if="!readOnly && !catalogLoading" :repository="repositoryUrl" :busy="registrationBusy" @submit="setRepository" />
      <p v-if="registrationError" class="input-error" role="alert">{{ registrationError }}</p>
      <a class="text-button" href="#/feed">フィードに戻る</a>
    </div>
    <div ref="workspaceElement" class="feed-workspace" :style="paneStyle" tabindex="-1"
      :class="{ 'article-page': articlePage, 'is-split': splitView, 'is-detail-scroll': fullPaneScroll, 'is-single': !detailTarget }">
      <section v-if="listPage" class="list-panel" :tabindex="splitView ? 0 : undefined" aria-label="記事一覧" :aria-busy="loading">
        <p v-if="!enabled && !catalogLoading">上の保存済み解析結果から、表示する結果を選択してください。</p>
        <FeedState v-else-if="loading && !items.length" state="loading" />
        <FeedState v-else-if="error && !items.length" state="error" :message="error" @retry="reload" />
        <FeedState v-else-if="!visibleItems.length" state="empty" @reset="resetFilters" />
        <FeedList v-else :items="visibleItems" :selected-id="selectedSummary?.id ?? null" :personalized="personalized"
          :repository-url="repositoryUrl" :full-features="false" :saved-ids="[]" @select="selectItem" />
      </section>
      <template v-if="detailTarget">
        <FeedState v-if="detailLoading" state="loading" />
        <FeedState v-else-if="detailError" state="error" :message="detailError" @retry="retryDetail" />
        <FeedDetail v-else-if="selected" :key="selected.id + ':' + repositoryUrl" :item="selected" :personalized="personalized"
          :expanded="articlePage" :full-features="false" :show-proof-of-concept="true" :show-sharing="true" :can-review="false" :repository-label="repositoryUrl.replace('https://github.com/', '')"
          @back="navigate(previousList)" @expand="expandArticle" />
      </template>
    </div>
  </main>
</template>

<style scoped>
.saved-analyses { margin-block: 16px; padding: 16px; border: 1px solid var(--line); background: var(--surface); }
.saved-analyses h2 { margin: 0 0 8px; font-size: 1.1rem; }
.saved-analyses ul { list-style: none; padding: 0; }
.saved-analyses li { margin-block: 12px; overflow-wrap: anywhere; }
.saved-analyses button { padding: 6px 10px; cursor: pointer; }
.saved-analyses summary { cursor: pointer; }
</style>
