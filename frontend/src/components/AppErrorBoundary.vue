<script setup lang="ts">
import { onErrorCaptured, ref } from 'vue'

const failed = ref(false)
onErrorCaptured(() => {
  failed.value = true
  return false
})
function reload() { window.location.reload() }
</script>

<template>
  <main v-if="failed" class="main-content empty-state" role="alert">
    <h1>画面を表示できませんでした</h1>
    <p>再読み込みして、もう一度お試しください。</p>
    <button type="button" class="primary-button" @click="reload">再読み込み</button>
  </main>
  <slot v-else />
</template>
