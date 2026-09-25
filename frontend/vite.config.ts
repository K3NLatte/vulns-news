import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    // Windows editors do not emit all filesystem events across the WSL mount.
    watch: { usePolling: process.env.VITE_USE_POLLING === 'true', interval: 300 },
  },
})
