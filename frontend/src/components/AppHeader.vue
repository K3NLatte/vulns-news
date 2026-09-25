<script setup lang="ts">
import { Bookmark, Search, Settings, UserRound } from '@lucide/vue'
import type { WorkspaceUser } from '../types/workspace'

defineProps<{
  user: WorkspaceUser | null
  fullFeatures: boolean
  page: string
  savedCount: number
  experimentalAnalysis?: boolean
}>()
defineEmits<{ account: [] }>()
</script>

<template>
  <header class="app-header">
    <a class="brand" href="#/feed" aria-label="vulns/news フィード">
      vulns<span class="brand-divider">/</span><span class="brand-news">news</span>
    </a>
    <nav v-if="fullFeatures" class="header-actions" aria-label="メインメニュー">
      <a href="#/saved" :aria-current="page === 'saved' ? 'page' : undefined">
        <Bookmark :size="19" aria-hidden="true" /><span>保存済み</span
        ><span v-if="savedCount" class="nav-count">{{ savedCount }}</span>
      </a>
      <a href="#/settings" :aria-current="page === 'settings' ? 'page' : undefined">
        <Settings :size="19" aria-hidden="true" /><span>設定</span>
      </a>
      <a v-if="experimentalAnalysis !== false" href="#/analyze" :aria-current="page === 'analyze' ? 'page' : undefined">
        <Search :size="19" aria-hidden="true" /><span>脆弱性を分析</span>
      </a>
      <button
        type="button"
        aria-haspopup="dialog"
        :aria-label="user ? `${user.displayName} のアカウントを開く` : 'ログイン'"
        @click="$emit('account')"
      >
        <UserRound :size="19" aria-hidden="true" /><span>{{ user?.displayName ?? 'ログイン' }}</span>
      </button>
    </nav>
  </header>
</template>
