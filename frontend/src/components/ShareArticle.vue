<script setup lang="ts">
import { nextTick, ref, useId, watch } from 'vue'
import { Share2 } from '@lucide/vue'
import { createArticleShareUrl } from '../utils/sharing'

const props = defineProps<{
  articleId: string
  title: string
  shareable?: boolean
}>()

const fieldId = useId()
const statusId = useId()
const panelId = useId()
const shareButton = ref<HTMLButtonElement>()
const urlField = ref<HTMLInputElement>()
const manualUrl = ref('')
const status = ref('')
const busy = ref(false)
let requestVersion = 0

watch(
  () => props.articleId,
  () => {
    requestVersion += 1
    manualUrl.value = ''
    status.value = ''
    busy.value = false
  },
)

function onPanelKeydown(event: KeyboardEvent) {
  if (event.key !== 'Escape' || event.isComposing || event.defaultPrevented) return
  event.preventDefault()
  event.stopPropagation()
  void closeManualCopy()
}

async function shareArticle() {
  if (busy.value) return
  if (props.shareable === false) {
    status.value = 'このレポートはこのブラウザーに保存されています。共有リンクは作成できません。'
    return
  }
  const version = ++requestVersion
  const url = createArticleShareUrl(window.location.href, props.articleId)
  const title = props.title
  busy.value = true
  manualUrl.value = ''
  status.value = ''

  try {
    if (typeof navigator.share === 'function') {
      try {
        await navigator.share({ title, url })
        if (version === requestVersion) status.value = '共有しました'
        return
      } catch (error) {
        if (error instanceof Error && error.name === 'AbortError') return
        if (version !== requestVersion) return
      }
    }

    try {
      await navigator.clipboard.writeText(url)
      if (version === requestVersion) status.value = 'リンクをコピーしました'
    } catch {
      if (version !== requestVersion) return
      manualUrl.value = url
      status.value = 'コピーできませんでした。URLを選択してコピーしてください。'
      await nextTick()
      if (version === requestVersion) {
        urlField.value?.focus({ preventScroll: true })
        urlField.value?.select()
      }
    }
  } finally {
    if (version === requestVersion) busy.value = false
  }
}

function selectUrl() {
  urlField.value?.focus({ preventScroll: true })
  urlField.value?.select()
}

async function closeManualCopy() {
  manualUrl.value = ''
  status.value = ''
  await nextTick()
  shareButton.value?.focus({ preventScroll: true })
}
</script>

<template>
  <div class="share-article">
    <button
      ref="shareButton"
      class="text-button"
      type="button"
      :aria-disabled="busy"
      :aria-busy="busy"
      :aria-expanded="Boolean(manualUrl)"
      :aria-controls="manualUrl ? panelId : undefined"
      @click="shareArticle"
    >
      <Share2 :size="18" aria-hidden="true" />
      共有
    </button>
    <span
      :id="statusId"
      class="share-status"
      :class="{ 'sr-only': manualUrl || !status }"
      role="status"
      aria-live="polite"
    >
      {{ status }}
    </span>
    <!-- eslint-disable-next-line vuejs-accessibility/no-static-element-interactions -- Child controls bubble Escape to this panel. -->
    <div
      v-if="manualUrl"
      :id="panelId"
      class="manual-copy"
      role="region"
      aria-label="リンクの共有"
      @keydown="onPanelKeydown"
    >
      <label :for="fieldId">共有URL</label>
      <p :id="statusId + '-manual'" class="share-status">{{ status }}</p>
      <input
        :id="fieldId"
        ref="urlField"
        type="text"
        :value="manualUrl"
        :aria-describedby="statusId + '-manual'"
        readonly
        spellcheck="false"
        @focus="selectUrl"
      />
      <div class="manual-copy-actions">
        <button class="text-button" type="button" @click="selectUrl">URLを選択</button>
        <button class="text-button" type="button" @click="closeManualCopy">閉じる</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.share-article {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 0 10px;
  min-width: 0;
  max-width: 100%;
}

.share-status {
  color: var(--muted);
  font-size: 0.875rem;
  line-height: 1.6;
  overflow-wrap: anywhere;
}

.manual-copy {
  flex-basis: 100%;
  width: min(420px, 100%);
  max-width: 100%;
  padding: 16px;
  border: 1px solid var(--line);
  background: var(--surface);
}

.manual-copy .share-status {
  margin-bottom: 10px;
}

.manual-copy label {
  display: block;
  margin-bottom: 6px;
  font-size: 0.875rem;
}

.manual-copy input {
  width: 100%;
  min-width: 0;
  font-size: 1rem;
}

.manual-copy-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}

.share-article > button[aria-disabled='true'] {
  opacity: 0.6;
  cursor: wait;
}
</style>
