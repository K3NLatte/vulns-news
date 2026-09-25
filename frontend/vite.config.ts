import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: { '/api': 'http://127.0.0.1:8080' },
    // Windows editors do not emit all filesystem events across the WSL mount.
    watch: { usePolling: true, interval: 300 },
  },
  preview: { proxy: { '/api': 'http://127.0.0.1:8080' } },
})
