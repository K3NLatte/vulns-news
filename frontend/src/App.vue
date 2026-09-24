<script setup lang="ts">
import { computed, nextTick, onScopeDispose, ref, watch } from 'vue'
import { ArrowLeft, ChevronDown, GitBranch, Plus, X } from '@lucide/vue'
import AnalysisDesk from './components/AnalysisDesk.vue'
import { useReportLibrary } from './composables/useReportLibrary'
import { filterFeedItems } from './services/feed'
import AppHeader from './components/AppHeader.vue'
import AnalysisStatus from './components/AnalysisStatus.vue'
import { useFeedPanes } from './composables/useFeedPanes'
import { useAnalysisPreview } from './composables/useAnalysisPreview'
import AccountDialog from './components/AccountDialog.vue'
import WorkspaceSettings from './components/WorkspaceSettings.vue'
import FeedDetail from './components/FeedDetail.vue'
import FeedList from './components/FeedList.vue'
import FeedState from './components/FeedState.vue'
import FeedToolbar from './components/FeedToolbar.vue'
import RepositoryForm from './components/RepositoryForm.vue'
import { useFeed, type PreviewState } from './composables/useFeed'
import { articlePath, useNavigation } from './composables/useNavigation'
import { useWorkspace } from './composables/useWorkspace'
import type { FeedQuery, FeedSort, Severity } from './types/feed'
import type { ReviewStatus } from './types/workspace'

// Both review variants use the same components and data boundary.
const params = new URLSearchParams(window.location.search)
const fullFeatures = params.get('view') !== 'mvp'
const scenario = params.get('scenario')
const preview = ref<PreviewState>(scenario === 'loading' || scenario === 'empty' || scenario === 'error' ? scenario : 'ready')
const { route, navigate } = useNavigation()
if (!fullFeatures && (route.value.page === 'saved' || route.value.page === 'settings' || route.value.page === 'analyze')) navigate('#/feed')
const workspace = useWorkspace()
const library = useReportLibrary()
const { jobs: reportJobs, reports: trackedReports, lifecycles, now: reportNow, submissionError: reportError, storageError: reportStorageError, publicationQueue } = library
const { user, repositories, activeRepositoryId, savedIds, comments, storageError } = workspace
const accountOpen = ref(false)
const actionError = ref('')
const accountError = ref('')
const commentError = ref('')
const repositoryError = ref('')
const adHocRepository = ref('')
const search = ref('')
const settledSearch = ref('')
const severity = ref<Severity | 'all'>('all')
const sort = ref<FeedSort>('newest')
const previousList = ref('#/feed')
let previousScroll = 0
let previousListScroll = 0
let articleFocusTarget = 'detail-title'
let restoreScroll: number | null = null
let searchTimer: ReturnType<typeof setTimeout>

watch(search, value => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => { settledSearch.value = value.trim() }, 200)
})
onScopeDispose(() => clearTimeout(searchTimer))

const activeRepository = computed(() => repositories.value.find(repo => repo.id === activeRepositoryId.value))
const repositoryUrl = computed(() => {
  if (route.value.page === 'article') return route.value.repositoryUrl ?? ''
  if (route.value.page !== 'repositories') return ''
  return fullFeatures ? activeRepository.value?.url ?? '' : adHocRepository.value
})
const personalized = computed(() => Boolean(repositoryUrl.value))
const articlePage = computed(() => route.value.page === 'article')
const listPage = computed(() => ['feed', 'repositories', 'saved'].includes(route.value.page))
const workspaceElement = ref<HTMLElement | null>(null)
const controlsElement = ref<HTMLElement | null>(null)
const { splitView, paneStyle } = useFeedPanes(workspaceElement, controlsElement, listPage)
const savedView = computed(() => route.value.page === 'saved')
const enabled = computed(() => route.value.page !== 'settings' && route.value.page !== 'analyze' && (route.value.page !== 'repositories' || personalized.value))

watch(personalized, value => {
  if (!value && sort.value === 'relevance') sort.value = 'newest'
})
const query = computed<FeedQuery>(() => ({
  scope: personalized.value ? 'repository' : 'all',
  repositoryUrl: repositoryUrl.value || undefined,
  search: articlePage.value ? '' : settledSearch.value,
  severity: articlePage.value ? 'all' : severity.value,
  sort: sort.value,
}))
const { items, selectedId, loading, error, reload } = useFeed(query, enabled, preview)
const combinedItems = computed(() => {
  const extras = fullFeatures ? library.additions(repositoryUrl.value) : []
  const unique = [...new Map([...items.value, ...extras].map(item => [item.id, item])).values()]
  return filterFeedItems(unique, query.value)
})
const analysis = useAnalysisPreview(combinedItems, personalized, params.get('analysis'))
const repositoryScan = computed(() => library.scanFor(repositoryUrl.value))
watch(repositoryUrl, url => {
  if (url && fullFeatures && !params.has('analysis') && !library.scanFor(url)) library.scanRepository(url)
}, { immediate: true })
const { filter: analysisFilter, analyzedCount, pendingCount, snapshot: analysisSnapshot } = analysis
const availableItems = computed(() => personalized.value ? analysis.items.value : combinedItems.value)
const visibleItems = computed(() => availableItems.value.filter(item => {
  if (savedView.value && !savedIds.value.includes(item.id)) return false
  return !personalized.value || analysisFilter.value === 'all' || item.repositoryAnalysis === analysisFilter.value
}))
const analysisWaiting = computed(() => personalized.value && ['queued', 'profiling', 'matching'].includes(analysis.stage.value))
const selected = computed(() => {
  const current = route.value
  if (current.page === 'article') return availableItems.value.find(item => item.id === current.articleId) ?? (fullFeatures ? library.catalog.value.find(item => item.id === current.articleId) : null) ?? null
  return visibleItems.value.find(item => item.id === selectedId.value) ?? visibleItems.value[0] ?? null
})
const articleComments = computed(() => comments.value.filter(comment => comment.articleId === selected.value?.id))
const reviewRepository = computed(() => repositories.value.find(repo => repo.url === repositoryUrl.value))
const reviewStatus = computed<ReviewStatus>(() => {
  if (!reviewRepository.value || !selected.value) return 'unreviewed'
  return workspace.getReviewStatus(reviewRepository.value.id, selected.value.id)
})
const hasFilters = computed(() => Boolean(search.value.trim()) || severity.value !== 'all')
const pageTitle = computed(() => savedView.value ? '保存した記事' : '脆弱性フィード')

watch(route, async (next, previous) => {
  if (!fullFeatures && (next.page === 'saved' || next.page === 'settings' || next.page === 'analyze')) {
    navigate('#/feed')
    return
  }
  if (next.page === 'article' && previous.page !== 'article') {
    selectedId.value = next.articleId
    previousList.value = '#/' + previous.page
    previousScroll = window.scrollY
    previousListScroll = document.querySelector('.list-panel')?.scrollTop ?? 0
  }
  if (previous.page === 'article' && next.page !== 'article') restoreScroll = previousScroll
  else { await nextTick(); window.scrollTo({ top: 0 }); }
})
watch(loading, async value => {
  if (value) return
  await nextTick()
  if (restoreScroll !== null) {
    window.scrollTo({ top: restoreScroll })
    const list = document.querySelector('.list-panel')
    if (list) list.scrollTop = previousListScroll
    restoreScroll = null
    document.getElementById('article-' + selectedId.value)?.focus({ preventScroll: true })
  } else if (articlePage.value) {
    const target = document.getElementById(articleFocusTarget)
    target?.focus({ preventScroll: true })
    if (articleFocusTarget === 'comments-heading') target?.scrollIntoView({ block: 'start' })
    articleFocusTarget = 'detail-title'
  }
})

function focusRepositoryInput() {
  document.getElementById('repository-url')?.focus()
}
function skipToContent() {
  document.getElementById('main-content')?.focus()
}
watch(accountOpen, value => { if (value) accountError.value = '' })
watch([() => selected.value?.id, user], () => { commentError.value = '' })

function addRepository(url: string) {
  const result = workspace.addRepository(url)
  repositoryError.value = result.ok ? '' : result.message
}
function setRepository(url: string) {
  if (!fullFeatures) { adHocRepository.value = url; return }
  addRepository(url)
}
function selectRepository(event: Event) {
  workspace.selectRepository((event.target as HTMLSelectElement).value)
}
function resetFilters() {
  search.value = ''
  settledSearch.value = ''
  severity.value = 'all'
}
function retry() {
  if (preview.value !== 'ready') preview.value = 'ready'
  else void reload()
}
async function selectItem(id: string) {
  selectedId.value = id
  if (!splitView.value) {
    navigate(articlePath(id, repositoryUrl.value || undefined))
    return
  }
  await nextTick()
  document.querySelector('.detail-content')?.scrollTo({ top: 0 })
  document.getElementById('detail-title')?.focus({ preventScroll: true })
}
function expandArticle(target = 'detail-title') {
  if (!selected.value) return
  articleFocusTarget = target
  navigate(articlePath(selected.value.id, repositoryUrl.value || undefined))
}
function runAction(action: () => void) {
  actionError.value = ''
  try { action() } catch (cause) {
    actionError.value = cause instanceof Error ? cause.message : '操作を完了できませんでした。'
  }
}
function toggleSaved(id: string) { runAction(() => workspace.toggleSaved(id)) }
function saveSelected() {
  if (selected.value) toggleSaved(selected.value.id)
}
function addComment(body: string) {
  commentError.value = ''
  try {
    if (selected.value) workspace.addComment(selected.value.id, body)
  } catch (cause) {
    commentError.value = cause instanceof Error ? cause.message : 'コメントを追加できませんでした。'
  }
}
function deleteComment(id: string) { runAction(() => workspace.deleteComment(id)) }
function changeReviewStatus(status: ReviewStatus) {
  const repository = reviewRepository.value
  const item = selected.value
  if (item && repository) runAction(() => workspace.setReviewStatus(repository.id, item.id, status))
}
function login(displayName: string) {
  accountError.value = ''
  try {
    workspace.login(displayName)
    accountOpen.value = false
  } catch (cause) {
    accountError.value = cause instanceof Error ? cause.message : 'ログインできませんでした。'
  }
}
function logout() {
  workspace.logout()
  accountOpen.value = false
}
</script>

<template>
  <a class="skip-link" href="#main-content" @click.prevent="skipToContent">本文に移動</a>
  <AppHeader :user="user" :full-features="fullFeatures" :page="route.page" :saved-count="savedIds.length" @account="accountOpen = true" />
  <main id="main-content" class="main-content" :class="{ 'is-feed': listPage }" tabindex="-1">
    <p v-if="storageError" class="storage-error" role="alert">{{ storageError }}</p>
    <p v-if="actionError" class="input-error" role="alert">{{ actionError }}</p>
    <p v-if="reportStorageError" class="storage-error" role="alert">{{ reportStorageError }}</p>
    <AnalysisDesk v-if="route.page === 'analyze' && fullFeatures" :jobs="reportJobs" :reports="trackedReports" :submission-error="reportError" :now="reportNow"
      @submit="library.submit" @reanalyze="library.reanalyze" @renew="library.renew" @retry="library.retry" @cancel="library.cancel" />
    <WorkspaceSettings
      v-else-if="route.page === 'settings' && fullFeatures"
      :repositories="repositories" :active-repository-id="activeRepositoryId" :user="user" :error="repositoryError"
      @add-repository="addRepository" @remove-repository="workspace.removeRepository"
      @select-repository="workspace.selectRepository" @login="accountOpen = true" @close="navigate('#/feed')"
    />
    <template v-else>
      <div v-if="!articlePage" ref="controlsElement" class="feed-controls">
        <div class="feed-heading-row">
        <div class="page-heading">
          <h1>{{ pageTitle }}</h1>
          <a v-if="savedView" class="text-button" href="#/feed"><ArrowLeft :size="18" aria-hidden="true" />フィードに戻る</a>
        </div>
        <nav v-if="!savedView" class="feed-views" aria-label="フィードの表示対象">
          <a href="#/feed" :aria-current="route.page === 'feed' ? 'page' : undefined">すべて</a>
          <a href="#/repositories" :aria-current="route.page === 'repositories' ? 'page' : undefined">リポジトリに関連</a>
        </nav>
        </div>
        <template v-if="route.page === 'repositories'">
          <div v-if="fullFeatures && repositories.length" class="repository-switcher">
            <GitBranch :size="20" aria-hidden="true" />
            <label class="sr-only" for="active-repository">表示するリポジトリ</label>
            <div class="select-control">
              <select id="active-repository" :value="activeRepositoryId ?? ''" @change="selectRepository">
                <option v-for="repo in repositories" :key="repo.id" :value="repo.id">{{ repo.label }}</option>
              </select>
              <ChevronDown :size="18" aria-hidden="true" />
            </div>
            <a href="#/settings" class="text-button"><Plus :size="18" aria-hidden="true" />追加・管理</a>
          </div>
          <RepositoryForm v-else :repository="adHocRepository" @submit="setRepository" />
          <p v-if="repositoryError" class="input-error" role="alert">{{ repositoryError }}</p>
        </template>
        <div v-if="fullFeatures && personalized && !params.has('analysis')" class="repository-history-status" role="status">
          <div>
            <strong>{{ repositoryScan?.status === 'completed' ? '過去の公開情報も検索済み' : repositoryScan?.status === 'cancelled' ? '過去情報の検索を中止しました' : '過去の公開情報も検索中' }}</strong>
            <span v-if="repositoryScan?.status === 'completed'">既存レポート {{ repositoryScan.reusedCount }}件を再利用 · {{ repositoryScan.newCount }}件を新規分析</span>
            <span v-else>既存レポートから表示しています。</span>
          </div>
          <a href="#/analyze" class="text-button">解析一覧</a>
          <button v-if="repositoryScan?.status === 'completed' || repositoryScan?.status === 'cancelled'" type="button" class="text-button" @click="library.scanRepository(repositoryUrl)">再検索</button>
        </div>
        <button v-if="fullFeatures && route.page === 'feed' && publicationQueue.length" type="button" class="new-reports-button" @click="library.publish">新しいレポート {{ publicationQueue.length }}件を表示</button>
        <AnalysisStatus v-if="personalized && !loading && !error && (params.has('analysis') || repositoryScan?.status === 'completed' || !fullFeatures)" :snapshot="analysisSnapshot" @retry="analysis.retry" />
        <FeedToolbar v-model:search="search" v-model:severity="severity" v-model:sort="sort" :allow-relevance-sort="personalized" />
        <div class="results-heading">
          <div v-if="personalized && !loading && !error" class="analysis-filters" role="group" aria-label="解析結果の絞り込み">
            <button type="button" :aria-pressed="analysisFilter === 'all'" @click="analysisFilter = 'all'">すべて <span>{{ availableItems.length }}</span></button>
            <button type="button" :aria-pressed="analysisFilter === 'analyzed'" @click="analysisFilter = 'analyzed'">分析済み <span>{{ analyzedCount }}</span></button>
            <button type="button" :aria-pressed="analysisFilter === 'pending'" @click="analysisFilter = 'pending'">未確定 <span>{{ pendingCount }}</span></button>
          </div>
          <p v-if="!personalized || loading || error" aria-live="polite" aria-atomic="true">
            <template v-if="loading">読み込み中</template>
            <template v-else-if="error">読み込みエラー</template>
            <template v-else-if="!enabled">リポジトリ未指定</template>
            <template v-else><strong>{{ visibleItems.length }}</strong> 件</template>
          </p>
          <button v-if="hasFilters" class="text-button" type="button" @click="resetFilters"><X :size="16" aria-hidden="true" />条件を解除</button>
        </div>
      </div>
      <div ref="workspaceElement" class="feed-workspace" :style="paneStyle" :class="{ 'article-page': articlePage, 'is-split': splitView, 'is-single': !selected || loading || error || !enabled }">
        <section v-if="!articlePage" class="list-panel" :tabindex="splitView ? 0 : undefined" aria-label="記事一覧" :aria-busy="loading">
          <FeedState v-if="!enabled" state="repository" @repositories="focusRepositoryInput" />
          <FeedState v-else-if="loading" state="loading" />
          <FeedState v-else-if="error" state="error" :message="error" @retry="retry" />
          <div v-else-if="analysisWaiting && !visibleItems.length" class="empty-state analysis-waiting">
            <h2>{{ analysis.stage.value === 'failed' ? '解析を再開してください' : '結果を待っています' }}</h2>
            <p>{{ analysis.stage.value === 'failed' ? '上の「再試行」から解析を再開できます。' : '確認できた記事からここに表示されます。' }}</p>
            <a href="#/feed" class="text-button">一般フィードを見る</a>
          </div>
          <FeedState v-else-if="!visibleItems.length" :state="savedView && !hasFilters ? 'saved' : 'empty'" @reset="resetFilters(); analysisFilter = 'all'" />
          <FeedList
            v-else :items="visibleItems" :selected-id="selected?.id ?? null" :personalized="personalized"
            :repository-url="repositoryUrl" :full-features="fullFeatures" :saved-ids="savedIds"
            @select="selectItem" @toggle-save="toggleSaved"
          />
        </section>
        <template v-if="articlePage">
          <FeedState v-if="loading" state="loading" />
          <FeedState v-else-if="error" state="error" :message="error" @retry="retry" />
          <div v-else-if="!selected" class="empty-state">
            <h1>記事が見つかりません</h1>
            <a class="text-button" href="#/feed">フィードに戻る</a>
          </div>
        </template>
        <FeedDetail
          v-if="selected && !loading && !error && enabled" :key="selected.id + ':' + repositoryUrl"
          :item="selected" :personalized="personalized" :expanded="articlePage" :full-features="fullFeatures"
          :lifecycle="lifecycles[selected.id]" :now="reportNow" :report-job="library.activeJobFor(selected.id)"
          @reanalyze="library.reanalyze(selected.id)" @renew="library.renew(selected.id)"
          :saved="savedIds.includes(selected.id)" :comments="articleComments" :current-user-id="user?.id ?? 'guest'"
          :review-status="reviewStatus" :can-review="Boolean(reviewRepository)" :comment-error="commentError" @back="navigate(previousList)" @expand="expandArticle()" @comments="expandArticle('comments-heading')"
          @toggle-save="saveSelected" @add-comment="addComment" @delete-comment="deleteComment"
          @update:review-status="changeReviewStatus"
        />
      </div>
    </template>
  </main>
  <AccountDialog v-if="fullFeatures" :open="accountOpen" :user="user" :submission-error="accountError" @login="login" @logout="logout" @close="accountOpen = false" />
</template>
