<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { X } from '@lucide/vue'
import { codePointLength } from '../utils/inputText'
import type { WorkspaceUser } from '../types/workspace'

const props = defineProps<{
  open: boolean
  user: WorkspaceUser | null
  submissionError?: string
  pending?: boolean
}>()

const emit = defineEmits<{
  login: [displayName: string]
  logout: []
  close: []
  'clear-error': []
}>()

const dialog = ref<HTMLDialogElement | null>(null)
const nameInput = ref<HTMLInputElement | null>(null)
const displayName = ref('')
const error = ref('')
const displayedError = computed(() => error.value || props.submissionError || '')
let previousFocus: HTMLElement | null = null

function restoreFocus() {
  if (previousFocus?.isConnected) {
    previousFocus.focus()
  }
  previousFocus = null
}

async function syncDialog() {
  const element = dialog.value
  if (!element) return

  if (props.open && !element.open) {
    previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    displayName.value = props.user?.displayName ?? ''
    error.value = ''
    element.showModal()

    if (!props.user) {
      await nextTick()
      if (props.open && element.open) {
        nameInput.value?.focus()
      }
    }
  } else if (!props.open && element.open) {
    element.close()
  }
}

function handleClose() {
  restoreFocus()
  if (props.open) {
    emit('close')
  }
}

function login() {
  if (props.pending) return
  const name = displayName.value.trim()
  if (!name) {
    error.value = '表示名を入力してください。'
    nameInput.value?.focus()
    return
  }
  if (codePointLength(name) > 40) {
    error.value = '表示名は40文字以内で入力してください。'
    nameInput.value?.focus()
    return
  }
  error.value = ''
  emit('login', name)
}

watch(() => props.open, syncDialog, { flush: 'post' })
onMounted(syncDialog)
onBeforeUnmount(() => {
  dialog.value?.close()
  restoreFocus()
})
function clearInputError() {
  error.value = ''
  emit('clear-error')
}
</script>

<template>
  <dialog
    ref="dialog"
    class="account-dialog"
    aria-labelledby="account-dialog-title"
    @cancel.prevent="emit('close')"
    @close="handleClose"
  >
    <header class="account-dialog-header">
      <h2 id="account-dialog-title">{{ user ? 'アカウント' : 'ログイン' }}</h2>
      <button class="icon-button" type="button" aria-label="閉じる" @click="emit('close')">
        <X :size="20" aria-hidden="true" />
      </button>
    </header>

    <div v-if="user" class="account-summary">
      <p class="account-name">{{ user.displayName }}</p>
      <p v-if="submissionError" class="input-error" role="alert">{{ submissionError }}</p>
      <div class="account-dialog-actions">
        <button
          class="secondary-button"
          type="button"
          :aria-disabled="pending"
          :aria-busy="pending"
          @click="!pending && emit('logout')"
        >
          ログアウト
        </button>
      </div>
    </div>

    <form v-else class="account-dialog-form" novalidate @submit.prevent="login">
      <label for="account-display-name">表示名</label>
      <input
        id="account-display-name"
        ref="nameInput"
        v-model="displayName"
        type="text"
        autocomplete="nickname"
        minlength="1"
        maxlength="80"
        required
        :aria-invalid="Boolean(displayedError)"
        :aria-describedby="displayedError ? 'account-name-error' : undefined"
        @input="clearInputError"
      />
      <p v-if="displayedError" id="account-name-error" class="input-error" role="alert">
        {{ displayedError }}
      </p>
      <div class="account-dialog-actions">
        <button class="secondary-button" type="button" @click="emit('close')">キャンセル</button>
        <button class="primary-button" type="submit" :aria-disabled="pending" :aria-busy="pending">ログイン</button>
      </div>
    </form>
  </dialog>
</template>
