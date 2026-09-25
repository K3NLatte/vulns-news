<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { ArrowLeft, Check, GitBranch, Plus, Trash2 } from '@lucide/vue'
import type { WorkspaceRepository, WorkspaceUser } from '../types/workspace'

const props = defineProps<{
  repositories: WorkspaceRepository[]
  activeRepositoryId: string | null
  user: WorkspaceUser | null
  error?: string
}>()

const emit = defineEmits<{
  'add-repository': [url: string]
  'remove-repository': [id: string]
  'select-repository': [id: string]
  login: []
  close: []
}>()

const repositoryUrl = ref('')
const urlInput = ref<HTMLInputElement | null>(null)
const pendingRemovalId = ref<string | null>(null)
let removalTrigger: HTMLButtonElement | null = null

watch(
  () => props.repositories.map(repository => repository.id),
  (ids, previousIds) => {
    if (ids.some(id => !previousIds.includes(id))) {
      repositoryUrl.value = ''
    }
    if (pendingRemovalId.value && !ids.includes(pendingRemovalId.value)) {
      pendingRemovalId.value = null
    }
  },
)

function addRepository() {
  const url = repositoryUrl.value.trim()
  if (url) {
    emit('add-repository', url)
  }
}

async function beginRemoval(id: string, event: MouseEvent) {
  removalTrigger = event.currentTarget instanceof HTMLButtonElement
    ? event.currentTarget
    : null
  pendingRemovalId.value = id
  await nextTick()
  removalTrigger?.closest('.repository-entry')
    ?.querySelector<HTMLButtonElement>('.repository-confirm-actions button')?.focus()
}

async function cancelRemoval() {
  pendingRemovalId.value = null
  await nextTick()
  if (removalTrigger?.isConnected) {
    removalTrigger.focus()
  }
  removalTrigger = null
}

async function removeRepository(id: string) {
  pendingRemovalId.value = null
  removalTrigger = null
  emit('remove-repository', id)
  await nextTick()
  urlInput.value?.focus()
}
</script>

<template>
  <section class="settings-page" aria-labelledby="settings-title">
    <header class="settings-heading">
      <h1 id="settings-title">設定</h1>
      <button class="text-button settings-back" type="button" @click="emit('close')">
        <ArrowLeft :size="16" aria-hidden="true" />
        フィードに戻る
      </button>
    </header>

    <section class="repository-manager" aria-labelledby="repositories-heading">
      <h2 id="repositories-heading">公開リポジトリ</h2>
      <form class="repository-add-form" @submit.prevent="addRepository">
        <label for="settings-repository-url">GitHubリポジトリのURL</label>
        <div class="repository-add-row">
          <input
            id="settings-repository-url"
            ref="urlInput"
            v-model="repositoryUrl"
            type="text"
            maxlength="2048"
            autocapitalize="off"
            inputmode="url"
            autocomplete="off"
            spellcheck="false"
            placeholder="https://github.com/owner/repository"
            required
            :aria-invalid="Boolean(error)"
            :aria-describedby="error ? 'settings-repository-error' : undefined"
          />
          <button class="primary-button" type="submit">
            <Plus :size="16" aria-hidden="true" />
            追加
          </button>
        </div>
        <p v-if="error" id="settings-repository-error" class="input-error" role="alert">
          {{ error }}
        </p>
      </form>

      <ul v-if="repositories.length" class="repository-list" aria-label="登録したリポジトリ">
        <li
          v-for="repository in repositories"
          :key="repository.id"
          class="repository-entry"
          :class="{ 'is-active': activeRepositoryId === repository.id }"
        >
          <div class="repository-entry-main">
            <GitBranch :size="18" aria-hidden="true" />
            <div>
              <strong>{{ repository.label }}</strong>
              <span class="repository-url">{{ repository.url }}</span>
            </div>
          </div>
          <div class="repository-entry-actions">
            <button
              class="secondary-button repository-selection"
              type="button"
              :aria-pressed="activeRepositoryId === repository.id"
              :aria-label="`${repository.label}を表示対象に選択`"
              @click="emit('select-repository', repository.id)"
            >
              <Check v-if="activeRepositoryId === repository.id" :size="15" aria-hidden="true" />
              {{ activeRepositoryId === repository.id ? '選択中' : '選択' }}
            </button>
            <button
              class="text-button repository-remove"
              type="button"
              :aria-label="`${repository.label}を削除`"
              :aria-expanded="pendingRemovalId === repository.id"
              @click="beginRemoval(repository.id, $event)"
            >
              <Trash2 :size="15" aria-hidden="true" />
              削除
            </button>
          </div>
          <div
            v-if="pendingRemovalId === repository.id"
            class="repository-remove-confirm"
            role="group"
            @keydown.esc.prevent="cancelRemoval"
            :aria-label="`${repository.label}の削除確認`"
          >
            <p>「{{ repository.label }}」を削除しますか？</p>
            <div class="repository-confirm-actions">
              <button
                class="secondary-button"
                type="button"
                @click="cancelRemoval"
              >
                キャンセル
              </button>
              <button
                class="secondary-button danger-button"
                type="button"
                @click="removeRepository(repository.id)"
              >
                削除する
              </button>
            </div>
          </div>
        </li>
      </ul>
      <p v-else class="repository-empty">リポジトリはまだ登録されていません。</p>
    </section>

    <section class="settings-account" aria-labelledby="settings-account-heading">
      <div>
        <h2 id="settings-account-heading">アカウント</h2>
        <p v-if="user" class="settings-account-name">{{ user.displayName }}</p>
        <p v-else>ログインすると登録したリポジトリを保存できます。</p>
      </div>
      <button class="secondary-button" type="button" @click="emit('login')">
        {{ user ? 'アカウントを開く' : 'ログイン' }}
      </button>
    </section>
  </section>
</template>
