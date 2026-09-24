<script setup lang="ts">
import { ref, watch } from 'vue'
import { ArrowRight, GitBranch } from '@lucide/vue'
import { parseRepositoryUrl } from '../services/feed'
const props = defineProps<{ repository: string }>()
const emit = defineEmits<{ submit: [url: string, label: string] }>()
const draft = ref(props.repository)
const error = ref('')
watch(() => props.repository, value => { draft.value = value; error.value = '' })
function submit() {
  const result = parseRepositoryUrl(draft.value)
  if (!result.ok) { error.value = result.message; return }
  error.value = ''
  draft.value = result.url
  emit('submit', result.url, result.label)
}
function useExample() {
  draft.value = 'https://github.com/example/atlas-console'
  submit()
}
</script>

<template>
  <form class="repository-form" @submit.prevent="submit">
    <div class="repository-heading"><GitBranch :size="18" aria-hidden="true" /><label for="repository-url">公開リポジトリ</label></div>
    <div class="repository-input-row">
      <input id="repository-url" v-model="draft" type="text" inputmode="url" autocomplete="off" spellcheck="false" placeholder="https://github.com/owner/repository" :aria-invalid="Boolean(error)" :aria-describedby="error ? 'repository-hint repository-error' : 'repository-hint'" @input="error = ''" />
      <button class="primary-button" type="submit">このURLで表示 <ArrowRight :size="16" aria-hidden="true" /></button>
    </div>
    <p v-if="error" id="repository-error" class="input-error" role="alert">{{ error }}</p>
    <p id="repository-hint" class="repository-hint">GitHubの公開リポジトリを想定しています。このモックはURLを送信せず、共通のサンプル依存構成を表示します。</p>
    <button class="text-button" type="button" @click="useExample">サンプルURLで試す <ArrowRight :size="14" aria-hidden="true" /></button>
  </form>
</template>
