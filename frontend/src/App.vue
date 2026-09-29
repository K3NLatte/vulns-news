<script setup lang="ts">
import { defineAsyncComponent } from 'vue'
import ApiApp from './ApiApp.vue'

// デザイン確認用の画面は明示的な開発設定でのみ使用する。
const PreviewApp = import.meta.env.DEV && import.meta.env.VITE_FEED_SOURCE === 'local'
  ? defineAsyncComponent(() => import('./PreviewApp.vue')) : null
</script>

<template>
  <component :is="PreviewApp ?? ApiApp" />
</template>