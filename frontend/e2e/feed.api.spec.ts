import { test, expect } from '@playwright/test'
import type { FeedResult } from '../src/types/feed'

const articles = '脆弱性記事'

test('製品名は狭い画面で文字を拡大しても読み取れ、キーボードでフィードへ戻れる', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 812 })
  await page.goto('/#/repositories')
  await page.evaluate(() => { document.documentElement.style.fontSize = '200%' })
  const brand = page.getByRole('link', { name: 'とりあーじアナウンサー フィード', exact: true })
  await expect(brand).toBeVisible()
  await expect(page).toHaveTitle(/とりあーじアナウンサー$/)
  await expect.poll(() => brand.evaluate(element => {
    const rect = element.getBoundingClientRect()
    return rect.left >= 0 && rect.right <= innerWidth && element.scrollWidth <= element.clientWidth
  })).toBe(true)
  await brand.focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/#\/feed$/)
  await page.getByRole('button', { name: 'example/archive-app — 結果を開く', exact: true }).click()
  const repository = page.locator('.active-repository')
  await expect(repository).toContainText('https://github.com/example/archive-app')
  await expect.poll(() => repository.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true)
})

test('imported partial analysis survives restart and opens without registration', async ({ page, request }) => {
  const writes: string[] = []
  const errors: string[] = []
  page.on('request', req => { if (req.method() !== 'GET') writes.push(req.method() + ' ' + req.url()) })
  page.on('pageerror', error => errors.push(error.message))
  const catalogResponse = await request.get('/api/analyses')
  expect(catalogResponse.status()).toBe(200)
  const catalog = await catalogResponse.json()
  expect(catalog.readOnly).toBe(true)
  expect(catalog.items).toHaveLength(1)
  const saved = catalog.items[0]
  expect(saved.url).toBe('https://github.com/example/archive-app')
  expect(saved.job.stage).toBe('failed')
  expect(saved.itemCount).toBe(1)
  const response = await request.get(`/api/repositories/${saved.job.repository_id}/feed`)
  expect(response.status()).toBe(200)
  const feed = await response.json() as FeedResult
  expect(feed.items).toHaveLength(1)
  const article = feed.items[0]!

  await page.goto('/')
  await expect(page.getByText('読み取り専用：', { exact: false })).toBeVisible()
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'example/archive-app — 結果を開く', exact: true }).click()
  await expect(page.getByRole('list', { name: articles, exact: true }).getByRole('listitem')).toHaveCount(1)
  await expect(page.getByLabel('リポジトリの解析状況')).not.toContainText('解析完了')
  await expect(page.locator('.feed-detail')).toContainText(article.summary)
  await page.getByLabel('記事を検索').fill('definitely-absent')
  await expect(page.getByRole('list', { name: articles, exact: true })).toHaveCount(0)
  await page.getByLabel('記事を検索').fill(article.advisoryId)
  await expect(page.getByRole('list', { name: articles, exact: true }).getByRole('listitem')).toHaveCount(1)
  await page.getByRole('button', { name: 'ページで開く', exact: true }).click()
  await page.reload()
  await expect(page.locator('#detail-title')).toBeVisible()
  await expect(page.locator('.feed-detail')).toContainText(article.summary)
  expect(writes).toEqual([])
  expect(errors).toEqual([])
})

test('saved article opens in a fresh mobile session without POST', async ({ page, request }) => {
  const response = await request.get('/api/cves')
  const feed = await response.json() as FeedResult
  const article = feed.items[0]!
  const writes: string[] = []
  page.on('request', req => { if (req.method() !== 'GET') writes.push(req.method()) })
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto(`/#/article/${encodeURIComponent(article.id)}?repository=${encodeURIComponent('https://github.com/example/archive-app')}`)
  await expect(page.locator('#detail-title')).toBeVisible()
  await expect(page.locator('.feed-detail')).toContainText(article.summary)
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  expect(writes).toEqual([])
})

test('catalog failure is visible and can be retried against the real API', async ({ page }) => {
  await page.route('**/api/analyses', route => route.fulfill({ status: 405, body: 'PRIVATE_ERROR' }))
  await page.goto('/')
  await expect(page.getByRole('alert')).toContainText('HTTP 405')
  await expect(page.locator('body')).not.toContainText('PRIVATE_ERROR')
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveCount(0)
  await page.unroute('**/api/analyses')
  await page.getByRole('button', { name: '再取得', exact: true }).click()
  await expect(page.getByRole('button', { name: 'example/archive-app — 結果を開く', exact: true })).toBeVisible()
})
