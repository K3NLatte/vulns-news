<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { MessageSquare, Trash2 } from '@lucide/vue'
import { codePointLength } from '../utils/inputText'
import { dateTime } from '../utils/presentation'
import type { FeedComment } from '../types/workspace'

const props = withDefaults(
  defineProps<{
    comments: FeedComment[]
    currentUserId: string
    submissionError?: string
    draft?: string
    submitting?: boolean
    submissionId?: number
    removalPendingId?: string
  }>(),
  {
    submissionError: '',
  },
)

const emit = defineEmits<{
  add: [body: string]
  remove: [id: string]
  'update:draft': [value: string]
  'clear-error': []
}>()

const localDraft = ref('')
const draft = computed({
  get: () => props.draft ?? localDraft.value,
  set: (value) => {
    localDraft.value = value
    emit('update:draft', value)
  },
})
const pendingRemovalId = ref<string | null>(null)
let removalTrigger: HTMLButtonElement | null = null
const commentInput = ref<HTMLTextAreaElement | null>(null)
const error = ref('')
const status = ref('')
const visibleError = computed(() => error.value || props.submissionError)
const maxLength = 2000
const formatDate = dateTime

watch(
  () => props.submissionId,
  (id, previousId) => {
    if (id !== previousId) {
      draft.value = ''
      error.value = ''
      status.value = 'コメントが追加されました。'
    }
  },
)

watch(
  () => props.currentUserId,
  () => {
    localDraft.value = ''
    error.value = ''
    status.value = ''
  },
)

function addComment() {
  if (props.submitting) return
  const body = draft.value.trim()
  error.value = ''
  status.value = ''
  if (!props.currentUserId) {
    error.value = 'コメントするにはログインしてください。'
    return
  }
  if (!body) {
    error.value = 'コメントを入力してください。'
    commentInput.value?.focus()
    return
  }
  if (codePointLength(body) > maxLength) {
    error.value = 'コメントは2,000文字以内で入力してください。'
    commentInput.value?.focus()
    return
  }
  emit('add', body)
}

function removeComment(comment: FeedComment) {
  if (props.currentUserId && comment.authorId === props.currentUserId) {
    emit('remove', comment.id)
  }
}

async function beginRemoval(id: string, event: MouseEvent) {
  removalTrigger = event.currentTarget as HTMLButtonElement
  pendingRemovalId.value = id
  await nextTick()
  removalTrigger.closest('.comment')?.querySelector<HTMLButtonElement>('.repository-confirm-actions button')?.focus()
}
async function cancelRemoval() {
  pendingRemovalId.value = null
  await nextTick()
  removalTrigger?.focus()
}
watch(
  () => props.comments.map((comment) => comment.id),
  async (ids) => {
    if (pendingRemovalId.value && !ids.includes(pendingRemovalId.value)) {
      pendingRemovalId.value = null
      status.value = 'コメントが削除されました。'
      await nextTick()
      commentInput.value?.focus()
    }
  },
)
function clearInputError() {
  error.value = ''
  emit('clear-error')
}
</script>

<template>
  <section class="comment-thread detail-section" aria-labelledby="comments-heading">
    <div class="section-heading">
      <h2 id="comments-heading" tabindex="-1">
        <MessageSquare :size="18" aria-hidden="true" />
        コメント
        <span class="comment-total">{{ comments.length }}件</span>
      </h2>
    </div>

    <p v-if="!comments.length" class="comments-empty">コメントはまだありません。</p>
    <ol v-else class="comment-list">
      <li v-for="(comment, index) in comments" :key="comment.id">
        <article class="comment">
          <header class="comment-header">
            <span class="comment-author">{{ comment.authorName }}</span>
            <time class="comment-date" :datetime="comment.createdAt">
              {{ formatDate(comment.createdAt) }}
            </time>
            <button
              v-if="currentUserId && comment.authorId === currentUserId"
              class="text-button comment-delete"
              type="button"
              :aria-label="'削除：' + comment.body.slice(0, 60) + '（' + (index + 1) + '件目）'"
              :aria-expanded="pendingRemovalId === comment.id"
              @click="beginRemoval(comment.id, $event)"
            >
              <Trash2 :size="17" aria-hidden="true" />
              削除
            </button>
          </header>
          <p class="comment-body">{{ comment.body }}</p>
          <!-- eslint-disable-next-line vuejs-accessibility/no-static-element-interactions -- Child controls bubble Escape to this panel. -->
          <div
            v-if="pendingRemovalId === comment.id"
            class="repository-remove-confirm"
            role="group"
            aria-label="コメントの削除確認"
            @keydown.esc.prevent.stop="cancelRemoval"
          >
            <p>このコメントを削除しますか？</p>
            <div class="repository-confirm-actions">
              <button class="secondary-button" type="button" @click="cancelRemoval">キャンセル</button>
              <button
                class="secondary-button danger-button"
                type="button"
                :aria-disabled="removalPendingId === comment.id"
                :aria-busy="removalPendingId === comment.id"
                @click="removalPendingId !== comment.id && removeComment(comment)"
              >
                削除する
              </button>
            </div>
          </div>
        </article>
      </li>
    </ol>

    <form class="comment-form" @submit.prevent="addComment">
      <label for="article-comment">コメントを追加</label>
      <textarea
        id="article-comment"
        ref="commentInput"
        v-model="draft"
        name="comment"
        rows="4"
        :maxlength="maxLength * 2"
        :disabled="!currentUserId"
        :aria-invalid="Boolean(visibleError)"
        :aria-describedby="visibleError ? 'comment-limit comment-error' : 'comment-limit'"
        placeholder="確認した内容や対応方針を共有"
        @input="clearInputError"
      ></textarea>
      <div class="comment-form-footer">
        <span id="comment-limit" class="comment-limit">{{ codePointLength(draft) }} / 2,000文字</span>
        <button
          class="primary-button"
          type="submit"
          :disabled="!currentUserId"
          :aria-disabled="submitting"
          :aria-busy="submitting"
        >
          コメントを追加
        </button>
      </div>
      <p v-if="visibleError" id="comment-error" class="input-error" role="alert">{{ visibleError }}</p>
      <p class="comment-status" role="status">{{ status }}</p>
    </form>
  </section>
</template>
