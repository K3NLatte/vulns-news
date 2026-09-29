import { defineConfig, devices } from '@playwright/test'

const externalServer = process.env.PLAYWRIGHT_BASE_URL
export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.api.spec.ts',
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: externalServer ?? 'http://127.0.0.1:4174',
    viewport: { width: 1440, height: 1000 },
    locale: 'ja-JP',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], channel: process.env.PLAYWRIGHT_CHANNEL, viewport: { width: 1440, height: 1000 } } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'], viewport: { width: 1440, height: 1000 } } },
  ],
  webServer: externalServer ? undefined : {
    command: 'node node_modules/vite/bin/vite.js --host 127.0.0.1 --port 4174 --strictPort',
    env: { VITE_FEED_SOURCE: 'api' },
    url: 'http://127.0.0.1:4174',
    reuseExistingServer: false,
  },
})
