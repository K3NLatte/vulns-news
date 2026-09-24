<script setup lang="ts">
import { nextTick, ref, useId, watch } from 'vue'
import { Share2 } from '@lucide/vue'
import { createArticleShareUrl } from '../utils/sharing'

const props = defineProps<{
  articleId: string
  title: string
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

watch(() => props.articleId, () => {
  requestVersion += 1
  manualUrl.value = ''
  status.value = ''
  busy.value = false
})

watch(manualUrl, (url, _previousUrl, onCleanup) => {
  if (!url) return
  const onKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') {
      event.preventDefault()
      void closeManualCopy()
    }
  }
  document.addEventListener('keydown', onKeydown)
  onCleanup(() => document.removeEventListener('keydown', onKeydown))
})

async function shareArticle() {
  if (busy.value) return
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
      :disabled="busy"
      :aria-expanded="Boolean(manualUrl)"
      :aria-controls="manualUrl ? panelId : undefined"
      @click="shareArticle"
    >
      <Share2 :size="18" aria-hidden="true" />
      共有
    </button>
    <span :id="statusId" class="share-status" :class="{ 'sr-only': manualUrl }" role="status" aria-live="polite">
      {{ status }}
    </span>
    <Teleport to="body">
      <div
        v-if="manualUrl"
        :id="panelId"
        class="manual-copy"
        role="region"
        aria-label="リンクの共有"
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
        >
        <div class="manual-copy-actions">
          <button class="text-button" type="button" @click="selectUrl">URLを選択</button>
          <button class="text-button" type="button" @click="closeManualCopy">閉じる</button>
        </div>
      </div>
    </Teleport>
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
  font-size: .875rem;
  line-height: 1.6;
  overflow-wrap: anywhere;
}

.share-status:empty {
  display: none;
}

.manual-copy {
  position: fixed;
  z-index: 20;
  right: 16px;
  bottom: 16px;
  width: min(420px, calc(100vw - 32px));
  max-height: 80dvh;
  overflow: auto;
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
  font-size: .875rem;
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

.share-article > button:disabled {
  opacity: .6;
  cursor: wait;
}
</style>
