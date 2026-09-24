import { defineConfig } from '@playwright/test'
import base from './playwright.config'

const externalServer = process.env.PLAYWRIGHT_PRODUCTION_URL
export default defineConfig(base, {
  testIgnore: [],
  testMatch: '**/*.production.spec.ts',
  use: { baseURL: externalServer ?? 'http://127.0.0.1:4175' },
  webServer: externalServer ? undefined : {
    command: 'pnpm preview --port 4175 --strictPort',
    url: 'http://127.0.0.1:4175',
    reuseExistingServer: false,
  },
})
