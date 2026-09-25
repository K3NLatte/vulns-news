<script setup lang="ts">
import { ref, watch } from 'vue'
import { ArrowRight } from '@lucide/vue'
import { parseRepositoryUrl } from '../services/feed'

const props = defineProps<{ repository: string }>()
const emit = defineEmits<{ submit: [url: string, label: string] }>()
const input = ref(props.repository)
const urlInput = ref<HTMLInputElement | null>(null)
const error = ref('')
watch(() => props.repository, value => { input.value = value; error.value = '' })

function submit() {
  const result = parseRepositoryUrl(input.value)
  if (!result.ok) {
    error.value = result.message
    urlInput.value?.focus()
    return
  }
  error.value = ''
  emit('submit', result.url, result.label)
}
</script>

<template>
  <form class="repository-form" @submit.prevent="submit">
    <label for="repository-url" class="repository-heading">公開リポジトリ</label>
    <div class="repository-input-row">
      <input
        id="repository-url" ref="urlInput" v-model="input" type="url" maxlength="2048" autocapitalize="off" placeholder="https://github.com/owner/repository"
        autocomplete="url" spellcheck="false" required :aria-invalid="Boolean(error)"
        :aria-describedby="error ? 'repository-error' : undefined"
        @input="error = ''"
      />
      <button class="primary-button" type="submit">読み込む<ArrowRight :size="18" aria-hidden="true" /></button>
    </div>
    <p v-if="error" id="repository-error" class="input-error" role="alert">{{ error }}</p>
  </form>
</template>
