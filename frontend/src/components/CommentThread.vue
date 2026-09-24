<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { MessageSquare, Trash2 } from '@lucide/vue'
import type { FeedComment } from '../types/workspace'

const props = withDefaults(defineProps<{
  comments: FeedComment[]
  currentUserId: string
  submissionError?: string
}>(), {
  submissionError: '',
})

const emit = defineEmits<{
  add: [body: string]
  remove: [id: string]
}>()

const draft = ref('')
const error = ref('')
const status = ref('')
const visibleError = computed(() => error.value || props.submissionError)
const maxLength = 2000
const dateFormat = new Intl.DateTimeFormat('ja-JP', {
  year: 'numeric',
  month: 'numeric',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'Asia/Tokyo',
})

watch(() => props.comments.length, (count, previousCount) => {
  if (count > previousCount) {
    draft.value = ''
    error.value = ''
    status.value = 'コメントが追加されました。'
  }
  if (count < previousCount) status.value = 'コメントが削除されました。'
})

watch(() => props.currentUserId, () => {
  draft.value = ''
  error.value = ''
  status.value = ''
})

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '日時不明' : dateFormat.format(date)
}

function addComment() {
  const body = draft.value.trim()
  error.value = ''
  status.value = ''
  if (!props.currentUserId) {
    error.value = 'コメントするにはログインしてください。'
    return
  }
  if (!body) {
    error.value = 'コメントを入力してください。'
    return
  }
  if (body.length > maxLength) {
    error.value = 'コメントは2,000文字以内で入力してください。'
    return
  }
  emit('add', body)
}

function removeComment(comment: FeedComment) {
  if (props.currentUserId && comment.authorId === props.currentUserId) {
    emit('remove', comment.id)
  }
}
</script>

<template>
  <section class="comment-thread detail-section" aria-labelledby="comments-heading">
    <div class="section-heading">
      <h3 id="comments-heading" tabindex="-1">
        <MessageSquare :size="18" aria-hidden="true" />
        コメント
        <span class="comment-total">{{ comments.length }}件</span>
      </h3>
    </div>

    <p v-if="!comments.length" class="comments-empty">コメントはまだありません。</p>
    <ol v-else class="comment-list">
      <li v-for="comment in comments" :key="comment.id">
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
              :aria-label="formatDate(comment.createdAt) + 'の自分のコメントを削除'"
              @click="removeComment(comment)"
            >
              <Trash2 :size="17" aria-hidden="true" />
              削除
            </button>
          </header>
          <p class="comment-body">{{ comment.body }}</p>
        </article>
      </li>
    </ol>

    <form class="comment-form" @submit.prevent="addComment">
      <label for="article-comment">コメントを追加</label>
      <textarea
        id="article-comment"
        v-model="draft"
        name="comment"
        rows="4"
        :maxlength="maxLength"
        :disabled="!currentUserId"
        :aria-invalid="Boolean(visibleError)"
        :aria-describedby="visibleError ? 'comment-limit comment-error' : 'comment-limit'"
        placeholder="確認した内容や対応方針を共有"
        @input="error = ''"
      ></textarea>
      <div class="comment-form-footer">
        <span id="comment-limit" class="comment-limit">{{ draft.length }} / 2,000文字</span>
        <button class="primary-button" type="submit" :disabled="!currentUserId">
          コメントを追加
        </button>
      </div>
      <p v-if="visibleError" id="comment-error" class="input-error" role="alert">{{ visibleError }}</p>
      <p class="comment-status" role="status">{{ status }}</p>
    </form>
  </section>
</template>