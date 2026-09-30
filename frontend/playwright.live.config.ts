import { defineConfig, devices } from '@playwright/test'

// Run after importing saved results into .local/news and building frontend/dist.
// Explicitly disable the model even if OLLAMA_MODEL is set in the environment.
export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.live.spec.ts',
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    ...devices['Desktop Chrome'],
    baseURL: 'http://127.0.0.1:8180',
    viewport: { width: 1440, height: 1000 },
    locale: 'ja-JP',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'go run ../cmd/news-server -addr 127.0.0.1:8180 -data ../.local/news -frontend dist -model=""',
    url: 'http://127.0.0.1:8180/api/cves?limit=1',
    reuseExistingServer: false,
    timeout: 60_000,
  },
})
