<script setup lang="ts">
import type { Severity } from '../types/feed'
import { severityLabels } from '../utils/presentation'
defineProps<{ severity: Severity; score?: number | null }>()
</script>

<template>
  <span class="severity-badge" :class="`severity-${severity}`">
    <span class="severity-dot" aria-hidden="true"></span>
    {{ severityLabels[severity] }}<span v-if="score != null" class="severity-score">{{ score.toFixed(1) }}</span>
  </span>
</template>
