import { test, expect, type Page } from '@playwright/test'

// Start the Go mock API on port 8080 before running this suite.
const articles = (page: Page) => page.getByRole('list', { name: '脆弱性記事', exact: true })
test.beforeEach(async ({ page }) => {
  page.on('pageerror', error => { throw error })
})

test('loads the Go feed, searches and sorts it, and fetches the selected detail', async ({ page }) => {
  const requests: string[] = []
  page.on('request', request => { if (request.url().includes('/api/')) requests.push(new URL(request.url()).pathname) })
  await page.goto('/#/feed')
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await expect(page.locator('#detail-title')).toBeVisible()
  await page.getByLabel('記事を検索').fill('ｓａｍｐｌｅｖｉｅｗ')
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  await page.getByRole('button', { name: '検索をクリア' }).click()
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await page.getByLabel('CVSS重要度').selectOption('high')
  await expect(articles(page).getByRole('listitem')).toHaveCount(5)
  await page.getByLabel('CVSS重要度').selectOption('all')
  await page.getByLabel('並び順').selectOption('severity')
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await page.locator('#article-demo-012').click()
  await expect(page.locator('#detail-title')).toHaveText('エラーページに内部パスと構成情報が表示される')
  await expect(page.locator('#detail-title')).toBeFocused()
  expect(requests).toContain('/api/cves/demo-012')
  await page.getByRole('button', { name: 'ページで開く', exact: true }).click()
  await page.reload()
  await expect(page.locator('#detail-title')).toHaveText('エラーページに内部パスと構成情報が表示される')
  await expect(page).toHaveTitle(/DEMO-2026-012/)
})

test('registers without login, reads the job and repository feed, and opens scoped details', async ({ page }) => {
  const requests: string[] = []
  page.on('request', request => { if (request.url().includes('/api/')) requests.push(new URL(request.url()).pathname) })
  await page.goto('/?view=mvp#/repositories')
  await page.getByLabel('公開リポジトリ', { exact: true }).fill('https://github.com/example/mock-service')
  const registrationPromise = page.waitForResponse(response => new URL(response.url()).pathname === '/api/repositories' && response.request().method() === 'POST')
  await page.getByRole('button', { name: '読み込む' }).click()
  const registration = await registrationPromise
  expect(registration.status()).toBe(202)
  expect(await registration.json()).toEqual({ repository_id: 'repo-001', job_id: 'job-001' })
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  await expect(page.getByLabel('リポジトリの解析状況')).toContainText('解析完了')
  await expect(page.getByLabel('リポジトリの解析状況')).toContainText('処理済み 6 / 6件')
  await page.locator('#article-demo-005').click()
  await expect(page.locator('#detail-title')).toBeVisible()
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  expect(requests).toContain('/api/jobs/job-001')
  expect(requests).toContain('/api/repositories/repo-001/feed')
  expect(requests).toContain('/api/repositories/repo-001/feed/demo-005')
  await page.getByLabel('並び順').selectOption('relevance')
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  expect(requests.filter(path => path === '/api/repositories')).toHaveLength(1)
})

test('shows HTTP errors and retries without falling back to browser fixtures', async ({ page }) => {
  let fail = true
  await page.route('**/api/cves?limit=200', route => fail
    ? route.fulfill({ status: 500, contentType: 'text/plain', body: 'internal details' }) : route.continue())
  await page.goto('/#/feed')
  await expect(page.getByRole('alert')).toContainText('HTTP 500')
  await expect(articles(page)).toHaveCount(0)
  await expect(page.getByText('internal details')).toHaveCount(0)
  fail = false
  await page.getByRole('button', { name: '再試行', exact: true }).click()
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await expect(page.locator('#detail-title')).toBeVisible()

  await page.route('**/api/cves/demo-002', route => route.fulfill({ status: 404, body: 'not found' }))
  await page.locator('#article-demo-002').click()
  await expect(page.getByRole('alert')).toContainText('見つかりません')
  await expect(page.locator('#detail-title')).toHaveCount(0)
  await page.unroute('**/api/cves/demo-002')
  await page.getByRole('button', { name: '再試行', exact: true }).click()
  await expect(page.locator('#detail-title')).toHaveText('共有キャッシュのキー衝突で別ユーザーの応答が返る')
})
