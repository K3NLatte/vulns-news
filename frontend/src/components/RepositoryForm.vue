<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ArrowRight } from '@lucide/vue'
import { parseRepositoryUrl } from '../utils/repositoryUrl'

const props = defineProps<{ repository: string; submissionError?: string; pending?: boolean; draft?: string }>()
const emit = defineEmits<{ submit: [url: string, label: string]; 'clear-error': []; 'update:draft': [value: string] }>()
const localInput = ref(props.repository)
const input = computed({
  get: () => props.draft ?? localInput.value,
  set: (value) => {
    localInput.value = value
    emit('update:draft', value)
  },
})
const urlInput = ref<HTMLInputElement | null>(null)
const error = ref('')
watch(
  () => props.repository,
  (value) => {
    if (props.draft === undefined) localInput.value = value
    error.value = ''
  },
)

watch(
  () => props.draft,
  () => {
    error.value = ''
  },
)
watch(
  () => props.submissionError,
  (value) => {
    if (value) urlInput.value?.focus()
  },
)

function submit() {
  if (props.pending) return
  const result = parseRepositoryUrl(input.value)
  if (!result.ok) {
    error.value = result.message
    urlInput.value?.focus()
    return
  }
  error.value = ''
  emit('submit', input.value.trim(), result.label)
}
function clearInputError() {
  error.value = ''
  emit('clear-error')
}
</script>

<template>
  <form class="repository-form" novalidate @submit.prevent="submit">
    <label for="repository-url" class="repository-heading">公開リポジトリ</label>
    <div class="repository-input-row">
      <input
        id="repository-url"
        ref="urlInput"
        v-model="input"
        type="url"
        maxlength="2048"
        autocapitalize="off"
        placeholder="https://github.com/owner/repository"
        autocomplete="url"
        spellcheck="false"
        required
        :aria-invalid="Boolean(error || submissionError)"
        :aria-describedby="error || submissionError ? 'repository-error' : undefined"
        @input="clearInputError"
      />
      <button class="primary-button" type="submit" :aria-disabled="pending" :aria-busy="pending">
        読み込む<ArrowRight :size="18" aria-hidden="true" />
      </button>
    </div>
    <p v-if="error || submissionError" id="repository-error" class="input-error" role="alert">
      {{ error || submissionError }}
    </p>
  </form>
</template>
