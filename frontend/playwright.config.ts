import { defineConfig, devices } from '@playwright/test'

const externalServer = process.env.PLAYWRIGHT_BASE_URL
export default defineConfig({
  testDir: './e2e',
  testIgnore: ['**/*.production.spec.ts', '**/*.api.spec.ts'],
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  workers: 2,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: externalServer ?? 'http://127.0.0.1:4173',
    locale: 'ja-JP',
    timezoneId: 'Asia/Tokyo',
    reducedMotion: 'reduce',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], channel: process.env.PLAYWRIGHT_CHANNEL, viewport: { width: 1440, height: 1000 } } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'], viewport: { width: 1440, height: 1000 } } },
  ],
  webServer: externalServer ? undefined : {
    // The existing design suite exercises its standalone local scenarios.
    env: { VITE_FEED_SOURCE: 'local' },
    command: 'pnpm dev --port 4173 --strictPort',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
  },
})
