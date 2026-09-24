<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { X } from '@lucide/vue'
import type { WorkspaceUser } from '../types/workspace'

const props = defineProps<{
  open: boolean
  user: WorkspaceUser | null
  submissionError?: string
}>()

const emit = defineEmits<{
  login: [displayName: string]
  logout: []
  close: []
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
    previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null
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
  const name = displayName.value.trim()
  if (!name) {
    error.value = '表示名を入力してください。'
    nameInput.value?.focus()
    return
  }
  if (name.length > 40) {
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
      <button
        class="icon-button"
        type="button"
        aria-label="閉じる"
        @click="emit('close')"
      >
        <X :size="20" aria-hidden="true" />
      </button>
    </header>

    <div v-if="user" class="account-summary">
      <p class="account-name">{{ user.displayName }}</p>
      <div class="account-dialog-actions">
        <button class="secondary-button" type="button" @click="emit('logout')">
          ログアウト
        </button>
      </div>
    </div>

    <form v-else class="account-dialog-form" @submit.prevent="login">
      <label for="account-display-name">表示名</label>
      <input
        id="account-display-name"
        ref="nameInput"
        v-model="displayName"
        type="text"
        autocomplete="nickname"
        minlength="1"
        maxlength="40"
        required
        :aria-invalid="Boolean(displayedError)"
        :aria-describedby="displayedError ? 'account-name-error' : undefined"
        @input="error = ''"
      />
      <p v-if="displayedError" id="account-name-error" class="input-error" role="alert">
        {{ displayedError }}
      </p>
      <div class="account-dialog-actions">
        <button class="secondary-button" type="button" @click="emit('close')">
          キャンセル
        </button>
        <button class="primary-button" type="submit">ログイン</button>
      </div>
    </form>
  </dialog>
</template>
