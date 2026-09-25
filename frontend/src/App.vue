<script setup lang="ts">
import { computed, nextTick, onScopeDispose, ref, watch } from 'vue'
import { ArrowLeft, ChevronDown, GitBranch, Plus, X } from '@lucide/vue'
import AnalysisDesk from './components/AnalysisDesk.vue'
import { useReportLibrary } from './composables/useReportLibrary'
import { createLocalFeedLoader } from './services/localFeedLoader'
import { useReadingPosition } from './composables/useReadingPosition'
import { parseRepositoryUrl } from './utils/repositoryUrl'
import { getSavedReportItems } from './services/reports'
import { resolveRepositoryArticle, canReviewRepositoryArticle } from './services/repositoryAssessment'
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
import { useFeed } from './composables/useFeed'
import { readPreviewOptions } from './utils/previewOptions'
import { articlePath, useNavigation } from './composables/useNavigation'
import { useWorkspace } from './composables/useWorkspace'
import type { FeedItem, FeedQuery, FeedSort, Severity } from './types/feed'
import type { ReviewStatus } from './types/workspace'
import type { SavedReportReference } from './types/reports'

// Both review variants use the same components and data boundary.
const { fullFeatures, preview: requestedPreview, analysisStage } = readPreviewOptions(window.location.search)
// Experimental report workflows can be removed from a release without removing the feed.
const experimentalAnalysis = fullFeatures && import.meta.env.VITE_ENABLE_EXPERIMENTAL_ANALYSIS !== 'false'
const preview = ref(requestedPreview)
const { route, entryId, navigate, backTo } = useNavigation()
if (
  (!fullFeatures && ['saved', 'settings'].includes(route.value.page)) ||
  (!experimentalAnalysis && route.value.page === 'analyze')
)
  navigate('#/feed', true)
const workspace = useWorkspace()
const { user, repositories, activeRepositoryId, savedIds, savedReportReferences, comments, storageError } = workspace
const library = useReportLibrary(() => user.value?.id ?? null, experimentalAnalysis)
const {
  jobs: reportJobs,
  reports: trackedReports,
  lifecycles,
  now: reportNow,
  submissionError: reportError,
  storageError: reportStorageError,
  publicationQueue,
} = library
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
const trackingFilter = ref<'active' | 'expired'>('active')
const settingsReturn = ref('#/feed')
const commentDrafts = ref<Record<string, string>>({})
const analysisDrafts = ref<Record<string, string>>({})
const repositoryDrafts = ref<Record<string, string>>({})
const commentSubmissionId = ref(0)
let articleFocusTarget = 'detail-title'
let searchTimer: ReturnType<typeof setTimeout>

watch(search, (value) => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    settledSearch.value = value.trim()
  }, 200)
})
onScopeDispose(() => clearTimeout(searchTimer))

const activeRepository = computed(() => repositories.value.find((repo) => repo.id === activeRepositoryId.value))
const repositoryUrl = computed(() => {
  if (route.value.page === 'article') return route.value.repositoryUrl ?? ''
  if (route.value.page !== 'repositories') return ''
  return fullFeatures ? (activeRepository.value?.url ?? '') : adHocRepository.value
})
const personalized = computed(() => Boolean(repositoryUrl.value))
const articlePage = computed(() => route.value.page === 'article')
const listPage = computed(() => ['feed', 'repositories', 'saved'].includes(route.value.page))
const workspaceElement = ref<HTMLElement | null>(null)
const controlsElement = ref<HTMLElement | null>(null)
const { splitView, paneStyle, fullPaneScroll } = useFeedPanes(workspaceElement, controlsElement, listPage)
const savedView = computed(() => route.value.page === 'saved')
const enabled = computed(
  () =>
    route.value.page !== 'settings' &&
    route.value.page !== 'analyze' &&
    route.value.page !== 'not-found' &&
    (route.value.page !== 'repositories' || personalized.value),
)

watch(personalized, (value) => {
  if (!value && sort.value === 'relevance') sort.value = 'newest'
})
const query = computed<FeedQuery>(() => ({
  scope: personalized.value ? 'repository' : 'all',
  repositoryUrl: repositoryUrl.value || undefined,
  search: articlePage.value ? '' : settledSearch.value,
  severity: articlePage.value ? 'all' : severity.value,
  sort: sort.value,
}))
const localLoader = createLocalFeedLoader((url) => ({
  additions: experimentalAnalysis ? library.additions(url) : [],
  ...(savedView.value && fullFeatures
    ? { savedItems: [...savedReportItems.value, ...library.catalog.value], savedIds: savedIds.value }
    : {}),
}))
const {
  items,
  selectedId,
  loading,
  refreshing,
  rejectedCount,
  nextCursor,
  error,
  reload,
  invalidate,
  reset: resetFeed,
  loadMore,
} = useFeed(query, enabled, preview, localLoader)
useReadingPosition(route, entryId, loading, selectedId)
watch(
  () => user.value?.id ?? null,
  () => {
    void resetFeed()
  },
  { flush: 'sync' },
)
const savedReportItems = computed(() => getSavedReportItems(savedReportReferences.value))
// Retain only the article explicitly unsaved while reading it. Clear on navigation/profile change.
const openedSavedArticle = ref<{ owner: string; item: FeedItem; reference: SavedReportReference } | null>(null)
watch(
  [route, () => user.value?.id ?? 'guest'],
  () => {
    openedSavedArticle.value = null
  },
  { flush: 'sync' },
)
const combinedItems = items
const localAdditions = computed(() => (experimentalAnalysis ? library.additions(repositoryUrl.value) : []))
watch([savedView, savedIds, savedReportReferences, localAdditions], () => {
  void invalidate()
})
const analysis = useAnalysisPreview(combinedItems, personalized, analysisStage)
const repositoryScan = computed(() => library.scanFor(repositoryUrl.value))
const repositoryScanError = ref('')
watch([repositoryUrl, () => user.value?.id], () => {
  repositoryScanError.value = ''
})
const scanActive = computed(
  () => repositoryScan.value && ['queued', 'collecting', 'analyzing'].includes(repositoryScan.value.status),
)
const repositoryScanLabel = computed(() => {
  if (repositoryScanError.value) return '過去情報の検索を開始できませんでした'
  switch (repositoryScan.value?.status) {
    case 'completed':
      return '過去の公開情報も検索済み'
    case 'cancelled':
      return '過去情報の検索を中止しました'
    case 'failed':
      return '過去情報の検索に失敗しました'
    case 'queued':
      return '過去情報の検索を待機中'
    case 'collecting':
    case 'analyzing':
      return '過去の公開情報も検索中'
    default:
      return '過去情報は未検索'
  }
})
async function requestRepositoryScan() {
  const repository = repositoryUrl.value
  const owner = user.value?.id ?? 'guest'
  repositoryScanError.value = ''
  const result = await library.commands.scanRepository(repository)
  if (repositoryUrl.value !== repository || (user.value?.id ?? 'guest') !== owner) return
  if (!result.ok) repositoryScanError.value = result.message
}

const { filter: analysisFilter, analyzedCount, pendingCount, snapshot: analysisSnapshot } = analysis
const availableItems = computed(() => (personalized.value ? analysis.items.value : combinedItems.value))
const visibleItems = computed(() =>
  availableItems.value.filter((item) => {
    if (savedView.value && !savedIds.value.includes(item.id)) return false
    return !personalized.value || analysisFilter.value === 'all' || item.repositoryAnalysis === analysisFilter.value
  }),
)
const analysisWaiting = computed(
  () => personalized.value && ['queued', 'profiling', 'matching'].includes(analysis.stage.value),
)
const selected = computed(() => {
  const current = route.value
  if (current.page !== 'article') {
    return visibleItems.value.find((item) => item.id === selectedId.value) ?? visibleItems.value[0] ?? null
  }
  const available = availableItems.value.find((item) => item.id === current.articleId)
  if (available || !fullFeatures) return available ?? null
  const opened = openedSavedArticle.value
  const retained =
    opened?.owner === (user.value?.id ?? 'guest') && opened.item.id === current.articleId ? opened.item : null
  const fallback =
    library.catalog.value.find((item) => item.id === current.articleId) ??
    savedReportItems.value.find((item) => item.id === current.articleId) ??
    retained ??
    null
  return personalized.value ? resolveRepositoryArticle(fallback, availableItems.value) : fallback
})
const articleComments = computed(() => comments.value.filter((comment) => comment.articleId === selected.value?.id))
const reviewRepository = computed(() => repositories.value.find((repo) => repo.url === repositoryUrl.value))
const reviewStatus = computed<ReviewStatus>(() => {
  if (!reviewRepository.value || !selected.value) return 'unreviewed'
  return workspace.getReviewStatus(reviewRepository.value.id, selected.value.id)
})
const hasFilters = computed(() => Boolean(search.value.trim()) || severity.value !== 'all')
const pageTitle = computed(() =>
  savedView.value ? '保存した記事' : personalized.value ? 'リポジトリに関連する脆弱性' : '脆弱性フィード',
)
watch(
  [route, selected],
  () => {
    const current = route.value
    const title =
      current.page === 'article'
        ? (selected.value?.advisoryId ?? '記事')
        : current.page === 'not-found'
          ? 'ページが見つかりません'
          : current.page === 'settings'
            ? '設定'
            : current.page === 'analyze'
              ? '脆弱性を分析'
              : current.page === 'saved'
                ? '保存した記事'
                : current.page === 'repositories'
                  ? 'リポジトリに関連'
                  : '脆弱性フィード'
    document.title = title + ' | vulns-news'
  },
  { immediate: true },
)

watch(route, async (next, previous) => {
  actionError.value = ''
  repositoryError.value = ''
  if (
    (!fullFeatures && ['saved', 'settings'].includes(next.page)) ||
    (!experimentalAnalysis && next.page === 'analyze')
  ) {
    navigate('#/feed', true)
    return
  }
  if (next.page === 'settings' && previous.page !== 'settings') settingsReturn.value = '#/' + previous.page
  if (next.page === 'article') {
    selectedId.value = next.articleId
    if (previous.page !== 'article') previousList.value = '#/' + previous.page
    await nextTick()
    if (articleFocusTarget === 'comments-heading') {
      document.getElementById(articleFocusTarget)?.focus()
      articleFocusTarget = 'detail-title'
    }
  }
})
watch(splitView, async (value, previous) => {
  if (previous && !value && listPage.value && document.activeElement?.closest('.feed-detail')) {
    await nextTick()
    document.getElementById('article-' + selected.value?.id)?.focus()
  }
})
const ownerKey = computed(() => user.value?.id ?? 'guest')
const draftKey = computed(() => JSON.stringify([ownerKey.value, selected.value?.id]))
const commentDraft = computed({
  get: () => commentDrafts.value[draftKey.value] ?? '',
  set: (value) => {
    commentDrafts.value[draftKey.value] = value
    commentError.value = ''
  },
})
const analysisDraft = computed({
  get: () => analysisDrafts.value[ownerKey.value] ?? '',
  set: (value) => {
    analysisDrafts.value[ownerKey.value] = value
    library.clearSubmissionFeedback()
  },
})
function repositoryDraftKey(view: string) {
  return JSON.stringify([ownerKey.value, view])
}
function repositoryDraft(view: string) {
  return computed({
    get: () => repositoryDrafts.value[repositoryDraftKey(view)] ?? '',
    set: (value: string) => {
      repositoryDrafts.value[repositoryDraftKey(view)] = value
      repositoryError.value = ''
    },
  })
}
const repositoryFormDraft = repositoryDraft('repositories')
const settingsRepositoryDraft = repositoryDraft('settings')
const reportActionMessages = library.operationErrors
const submissionStatus = library.submissionMessage

function focusRepositoryInput() {
  document.getElementById('repository-url')?.focus()
}
function skipToContent() {
  document.getElementById('main-content')?.focus()
}
watch(accountOpen, (value) => {
  if (value) accountError.value = ''
})
watch([() => selected.value?.id, () => user.value?.id], () => {
  commentError.value = ''
})

async function addRepository(url: string) {
  const submittedKey = repositoryDraftKey(route.value.page)
  const result = await workspace.addRepository(url)
  repositoryError.value = result.ok ? '' : result.message
  if (result.ok) {
    if (repositoryDrafts.value[submittedKey]?.trim() === url.trim()) repositoryDrafts.value[submittedKey] = ''
    await nextTick()
    document.getElementById('active-repository')?.focus()
  }
}
function setRepository(url: string) {
  if (!fullFeatures) {
    const parsed = parseRepositoryUrl(url)
    if (parsed.ok) adHocRepository.value = parsed.url
    return
  }
  void addRepository(url)
}
async function selectRepository(event: Event) {
  const target = event.target
  if (!(target instanceof HTMLSelectElement)) return
  await runAction(() => workspace.selectRepository(target.value))
  target.value = activeRepositoryId.value ?? ''
}
async function selectStoredRepository(id: string) {
  await runAction(() => workspace.selectRepository(id))
}
async function removeRepository(id: string) {
  await runAction(() => workspace.removeRepository(id))
}
function resetFilters() {
  search.value = ''
  settledSearch.value = ''
  severity.value = 'all'
  analysisFilter.value = 'all'
  void nextTick(() => document.querySelector<HTMLInputElement>('input[type=search]')?.focus())
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
}
function focusDetail() {
  document.getElementById('detail-title')?.focus({ preventScroll: true })
}

function expandArticle(target = 'detail-title') {
  if (!selected.value) return
  articleFocusTarget = target
  navigate(articlePath(selected.value.id, repositoryUrl.value || undefined))
}
async function runAction(action: () => Promise<{ ok: boolean; message?: string }>) {
  actionError.value = ''
  const result = await action()
  if (!result.ok) actionError.value = result.message ?? '操作を完了できませんでした。再試行してください。'
  return result.ok
}
async function toggleSaved(id: string) {
  const owner = user.value?.id ?? 'guest'
  const opened = openedSavedArticle.value
  const reference =
    library.referenceFor(id) ??
    (Object.hasOwn(savedReportReferences.value, id) ? savedReportReferences.value[id] : undefined) ??
    (opened?.owner === owner && opened.item.id === id ? opened.reference : undefined)
  if (articlePage.value && selected.value?.id === id && savedIds.value.includes(id) && reference) {
    openedSavedArticle.value = { owner, item: selected.value, reference }
  }
  const focused = document.activeElement as HTMLElement | null
  await runAction(() => workspace.toggleSaved(id, reference))
  await nextTick()
  if (focused && !focused.isConnected) document.getElementById('article-' + selected.value?.id)?.focus()
}
function saveSelected() {
  if (selected.value) toggleSaved(selected.value.id)
}
async function addComment(body: string) {
  commentError.value = ''
  const article = selected.value
  if (!article) return
  const submittedKey = draftKey.value
  const submittedDraft = commentDraft.value
  const result = await workspace.addComment(article.id, body, library.referenceFor(article.id))
  const draftUnchanged = (commentDrafts.value[submittedKey] ?? '') === submittedDraft
  if (result.ok) {
    if (draftUnchanged) commentDrafts.value[submittedKey] = ''
    if (draftKey.value === submittedKey && draftUnchanged) commentSubmissionId.value++
  } else if (draftKey.value === submittedKey && draftUnchanged) commentError.value = result.message
}
function deleteComment(id: string) {
  void runAction(() => workspace.deleteComment(id))
}
function changeReviewStatus(status: ReviewStatus) {
  const repository = reviewRepository.value
  const item = selected.value
  if (item && repository && canReviewRepositoryArticle(item))
    void runAction(() => workspace.setReviewStatus(repository.id, item.id, status, library.referenceFor(item.id)))
}
async function login(displayName: string) {
  accountError.value = ''
  const result = await workspace.login(displayName)
  if (result.ok) accountOpen.value = false
  else accountError.value = result.message
}
async function logout() {
  accountError.value = ''
  const result = await workspace.logout()
  if (result.ok) accountOpen.value = false
  else accountError.value = result.message
}
async function publishReports() {
  library.publish()
  await invalidate()
  await nextTick()
  document.querySelector<HTMLElement>('main h1')?.focus()
}
async function focusAfterRemovedAction(trigger: Element | null) {
  await nextTick()
  if (trigger && !trigger.isConnected && document.activeElement === document.body)
    document.getElementById('main-content')?.focus()
}
async function reloadWorkspace() {
  const trigger = document.activeElement
  await runAction(() => workspace.reloadLatest())
  await focusAfterRemovedAction(trigger)
}
function exportRecovery() {
  const blob = new Blob([workspace.exportRecovery()], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'vulns-news-recovery.json'
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
async function recoverWorkspace() {
  const trigger = document.activeElement
  if (window.confirm('元の保存内容をバックアップして、復旧できるデータで再開しますか？')) {
    await runAction(() => workspace.resetRecovery())
    await focusAfterRemovedAction(trigger)
  }
}
</script>

<template>
  <a class="skip-link" href="#main-content" @click.prevent="skipToContent">本文に移動</a>
  <AppHeader
    :user="user"
    :full-features="fullFeatures"
    :experimental-analysis="experimentalAnalysis"
    :page="route.page"
    :saved-count="savedIds.length"
    @account="accountOpen = true"
  />
  <main id="main-content" class="main-content" :class="{ 'is-feed': listPage }" tabindex="-1">
    <div v-if="storageError" class="storage-error">
      <p role="alert">{{ storageError }}</p>
      <button type="button" class="text-button" @click="exportRecovery">保存内容をエクスポート</button>
      <button type="button" class="text-button" @click="reloadWorkspace">最新の保存内容を読み込む</button>
      <button v-if="workspace.recoveryAvailable.value" type="button" class="text-button" @click="recoverWorkspace">
        保存内容を復旧
      </button>
    </div>
    <p v-if="error && items.length" class="input-error" role="alert">
      {{ error }} <button class="text-button" @click="retry">再試行</button>
    </p>
    <p v-if="actionError" class="input-error" role="alert">{{ actionError }}</p>
    <p v-if="workspace.storageNotice.value" role="status" class="storage-notice">{{ workspace.storageNotice.value }}</p>
    <p v-if="reportStorageError" class="storage-error" role="alert">{{ reportStorageError }}</p>
    <div v-if="route.page === 'not-found'" class="empty-state">
      <h1 tabindex="-1">ページが見つかりません</h1>
      <a href="#/feed">フィードに戻る</a>
    </div>
    <AnalysisDesk
      v-else-if="route.page === 'analyze' && experimentalAnalysis"
      v-model:tracking-filter="trackingFilter"
      :pending="library.pending.value"
      :draft="analysisDraft"
      @update:draft="analysisDraft = $event"
      :action-messages="reportActionMessages"
      :submission-status="submissionStatus"
      @clear-error="library.clearSubmissionFeedback"
      @dismiss="library.commands.dismissJob"
      :jobs="reportJobs"
      :reports="trackedReports"
      :submission-error="reportError"
      :now="reportNow"
      @submit="library.commands.submit"
      @reanalyze="library.commands.reanalyze"
      @renew="library.commands.renew"
      @retry="library.commands.retry"
      @cancel="library.commands.cancel"
    />
    <WorkspaceSettings
      v-model:draft="settingsRepositoryDraft"
      v-else-if="route.page === 'settings' && fullFeatures"
      :repositories="repositories"
      :active-repository-id="activeRepositoryId"
      :user="user"
      :error="repositoryError"
      :pending="workspace.pending.value"
      @clear-error="repositoryError = ''"
      @add-repository="addRepository"
      @remove-repository="removeRepository"
      @select-repository="selectStoredRepository"
      @login="accountOpen = true"
      @close="backTo(settingsReturn)"
    />
    <template v-else>
      <div v-if="!articlePage" ref="controlsElement" class="feed-controls">
        <div class="feed-heading-row">
          <div class="page-heading">
            <h1>{{ pageTitle }}</h1>
            <a v-if="savedView" class="text-button" href="#/feed"
              ><ArrowLeft :size="18" aria-hidden="true" />フィードに戻る</a
            >
          </div>
          <nav v-if="!savedView" class="feed-views" aria-label="フィードの表示対象">
            <a href="#/feed" :aria-current="route.page === 'feed' ? 'page' : undefined">すべて</a>
            <a href="#/repositories" :aria-current="route.page === 'repositories' ? 'page' : undefined"
              >リポジトリに関連</a
            >
          </nav>
        </div>
        <template v-if="route.page === 'repositories'">
          <div v-if="fullFeatures && repositories.length" class="repository-switcher">
            <GitBranch :size="20" aria-hidden="true" />
            <label class="sr-only" for="active-repository">表示するリポジトリ</label>
            <div class="select-control">
              <select
                id="active-repository"
                :title="activeRepository?.label"
                :value="activeRepositoryId ?? ''"
                @change="selectRepository"
              >
                <option v-for="repo in repositories" :key="repo.id" :value="repo.id">{{ repo.label }}</option>
              </select>
              <ChevronDown :size="18" aria-hidden="true" />
            </div>
            <a href="#/settings" class="text-button"><Plus :size="18" aria-hidden="true" />追加・管理</a>
          </div>
          <RepositoryForm
            v-model:draft="repositoryFormDraft"
            v-else
            :pending="workspace.pending.value"
            :submission-error="repositoryError"
            @clear-error="repositoryError = ''"
            :repository="adHocRepository"
            @submit="setRepository"
          />
        </template>
        <div
          v-if="experimentalAnalysis && personalized && !Boolean(analysisStage)"
          class="repository-history-status"
          role="status"
        >
          <div>
            <strong>{{ repositoryScanLabel }}</strong>
            <span v-if="repositoryScan?.status === 'completed'"
              >既存レポート {{ repositoryScan.reusedCount }}件を再利用 · {{ repositoryScan.newCount }}件を新規分析</span
            >
            <span v-else>既存レポートから表示しています。</span>
          </div>
          <a href="#/analyze" class="text-button">解析一覧</a>
          <button
            type="button"
            class="text-button"
            :aria-disabled="Boolean(scanActive) || library.pending.value"
            :aria-busy="library.pending.value"
            @click="!scanActive && !library.pending.value && requestRepositoryScan()"
          >
            {{ repositoryScan ? '再検索' : '過去情報も検索' }}
          </button>
        </div>
        <p v-if="repositoryScanError" class="input-error" role="alert">{{ repositoryScanError }}</p>
        <p class="sr-only" role="status">
          {{ publicationQueue.length ? `新しいレポートが${publicationQueue.length}件あります` : '' }}
        </p>
        <AnalysisStatus
          v-if="personalized && !loading && !error && (Boolean(analysisStage) || !experimentalAnalysis)"
          :snapshot="analysisSnapshot"
          @retry="analysis.retry"
        />
        <FeedToolbar
          v-model:search="search"
          v-model:severity="severity"
          v-model:sort="sort"
          :allow-relevance-sort="personalized"
        />
        <div class="results-heading">
          <div
            v-if="personalized && !loading && !error"
            class="analysis-filters"
            role="group"
            aria-label="解析結果の絞り込み"
          >
            <button type="button" :aria-pressed="analysisFilter === 'all'" @click="analysisFilter = 'all'">
              すべて <span>{{ availableItems.length }}</span>
            </button>
            <button type="button" :aria-pressed="analysisFilter === 'analyzed'" @click="analysisFilter = 'analyzed'">
              分析済み <span>{{ analyzedCount }}</span>
            </button>
            <button type="button" :aria-pressed="analysisFilter === 'pending'" @click="analysisFilter = 'pending'">
              未確定 <span>{{ pendingCount }}</span>
            </button>
          </div>
          <p aria-live="polite" aria-atomic="true">
            <template v-if="loading">読み込み中</template>
            <template v-else-if="error">読み込みエラー</template>
            <template v-else-if="!enabled">リポジトリ未指定</template>
            <template v-else
              ><strong>{{ visibleItems.length }}</strong> 件<span v-if="refreshing"> · 更新中</span></template
            >
          </p>
          <button
            v-if="experimentalAnalysis && route.page === 'feed' && publicationQueue.length"
            type="button"
            class="new-reports-button"
            @click="publishReports"
          >
            新着 {{ publicationQueue.length }}件を表示
          </button>
          <button v-if="hasFilters" class="text-button" type="button" @click="resetFilters">
            <X :size="16" aria-hidden="true" />条件を解除
          </button>
        </div>
      </div>
      <p v-if="rejectedCount" role="status" class="input-error">
        形式を確認できない {{ rejectedCount }}件を除いて表示しています。
      </p>

      <div
        ref="workspaceElement"
        class="feed-workspace"
        :class="{
          'article-page': articlePage,
          'is-split': splitView,
          'is-detail-scroll': fullPaneScroll,
          'is-single': !selected || loading || !enabled,
        }"
      >
        <section v-if="!articlePage" class="list-panel" aria-label="記事一覧" :aria-busy="loading || refreshing">
          <FeedState v-if="!enabled" state="repository" @repositories="focusRepositoryInput" />
          <FeedState v-else-if="loading" state="loading" />
          <FeedState v-else-if="error && !items.length" state="error" :message="error" @retry="retry" />
          <div v-else-if="analysisWaiting && !visibleItems.length" class="empty-state analysis-waiting">
            <h2>{{ analysis.stage.value === 'failed' ? '解析を再開してください' : '結果を待っています' }}</h2>
            <p>
              {{
                analysis.stage.value === 'failed'
                  ? '上の「再試行」から解析を再開できます。'
                  : '確認できた記事からここに表示されます。'
              }}
            </p>
            <a href="#/feed" class="text-button">一般フィードを見る</a>
          </div>
          <FeedState
            v-else-if="!visibleItems.length"
            :state="savedView && !hasFilters ? 'saved' : 'empty'"
            :has-filters="hasFilters || analysisFilter !== 'all'"
            @reset="resetFilters"
          />
          <FeedList
            v-else
            :items="visibleItems"
            :selected-id="selected?.id ?? null"
            :personalized="personalized"
            :repository-url="repositoryUrl"
            :split-view="splitView"
            @focus-detail="focusDetail"
            :full-features="fullFeatures"
            :saved-ids="savedIds"
            @select="selectItem"
            @toggle-save="toggleSaved"
          />
          <button
            v-if="nextCursor"
            class="secondary-button"
            :aria-disabled="refreshing"
            :aria-busy="refreshing"
            @click="loadMore"
          >
            さらに読み込む
          </button>
        </section>
        <template v-if="articlePage">
          <div v-if="loading || error || !selected">
            <h1 v-if="loading">記事を読み込み中</h1>
            <button class="text-button" type="button" @click="backTo(previousList)">一覧に戻る</button>
          </div>
          <FeedState v-if="loading" state="loading" />
          <FeedState v-else-if="error && !items.length" state="error" :message="error" @retry="retry" />
          <div v-else-if="!selected" class="empty-state">
            <h1>記事が見つかりません</h1>
            <a class="text-button" href="#/feed">フィードに戻る</a>
          </div>
        </template>
        <FeedDetail
          v-if="selected && !loading && enabled"
          :style="paneStyle"
          :key="selected.id + ':' + repositoryUrl"
          :item="selected"
          :show-report-tracking="experimentalAnalysis"
          :report-pending="library.pending.value"
          :repository-url="repositoryUrl"
          :comment-draft="commentDraft"
          @update:comment-draft="commentDraft = $event"
          :comment-submitting="workspace.pending.value"
          :comment-submission-id="commentSubmissionId"
          @clear-comment-error="commentError = ''"
          :report-action-message="reportActionMessages[selected.id]"
          :personalized="personalized"
          :expanded="articlePage"
          :full-features="fullFeatures"
          :lifecycle="Object.hasOwn(lifecycles, selected.id) ? lifecycles[selected.id] : undefined"
          :now="reportNow"
          :report-job="library.activeJobFor(selected.id)"
          @reanalyze="library.commands.reanalyze(selected.id)"
          @renew="library.commands.renew(selected.id)"
          :saved="savedIds.includes(selected.id)"
          :comments="articleComments"
          :current-user-id="user?.id ?? 'guest'"
          :review-status="reviewStatus"
          :can-review="Boolean(reviewRepository) && canReviewRepositoryArticle(selected)"
          :repository-label="repositoryUrl.replace('https://github.com/', '')"
          :comment-error="commentError"
          @back="backTo(previousList)"
          @expand="expandArticle()"
          @comments="expandArticle('comments-heading')"
          @toggle-save="saveSelected"
          @add-comment="addComment"
          @delete-comment="deleteComment"
          @update:review-status="changeReviewStatus"
        />
      </div>
    </template>
  </main>
  <AccountDialog
    v-if="fullFeatures"
    :open="accountOpen"
    :user="user"
    :submission-error="accountError"
    :pending="workspace.pending.value"
    @clear-error="accountError = ''"
    @login="login"
    @logout="logout"
    @close="accountOpen = false"
  />
</template>
