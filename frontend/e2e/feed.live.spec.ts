import { test, expect } from '@playwright/test'
import type { FeedResult } from '../src/types/feed'

test('saved real analysis reaches the production UI without model calls or API mocks', async ({ page, request }) => {
  const writes: string[] = []
  page.on('request', req => { if (req.method() !== 'GET') writes.push(req.method() + ' ' + req.url()) })
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  const response = await request.get('/api/cves?limit=1')
  expect(response.ok()).toBeTruthy()
  const first = await response.json() as FeedResult
  expect(first.total, 'import existing analysis before running the live E2E').toBeGreaterThan(0)
  const article = first.items[0]!
  await page.goto('/#/feed')
  const articles = page.getByRole('list', { name: '脆弱性記事', exact: true })
  await expect(articles.getByRole('listitem')).toHaveCount(first.total)
  await expect(page.locator('#detail-title')).toBeVisible()
  await page.getByLabel('記事を検索').fill(article.advisoryId)
  await expect(articles.getByRole('listitem')).toHaveCount(1)
  await expect(page.locator('.feed-detail')).toContainText(article.summary)
  await expect(page.locator('.feed-detail')).toContainText('悪用状況は未確認')
  await page.getByRole('button', { name: 'ページで開く', exact: true }).click()
  await expect(page).toHaveURL(new RegExp('#/article/' + article.id + '$'))
  await page.reload()
  await expect(page.locator('#detail-title')).toBeVisible()

  await page.goto('/')
  await expect(page.getByText('読み取り専用：', { exact: false })).toBeVisible()
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'vercel/next.js — 結果を開く', exact: true }).click()
  await expect(articles.getByRole('listitem')).toHaveCount(first.total)
  await expect(page.getByLabel('リポジトリの解析状況')).toContainText('解析完了')
  await expect(page.getByRole('button', { name: /^分析済み/ })).toContainText('355')
  await expect(page.getByRole('button', { name: /^未確定/ })).toContainText('227')
  await expect(page.getByText('スキャン範囲に未確認の項目があります。', { exact: false })).toBeVisible()
  await page.getByRole('button', { name: /^未確定/ }).click()
  await expect(articles.getByRole('listitem')).toHaveCount(227)
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  await page.screenshot({ path: 'test-results/live-nextjs.png', fullPage: true })
  expect(errors).toEqual([])
  expect(writes).toEqual([])
})

test('saved repository article opens in a fresh session without registration', async ({ page }) => {
  const writes: string[] = []
  page.on('request', req => { if (req.method() !== 'GET') writes.push(req.method()) })
  await page.goto('/#/article/CVE-2015-8858?repository=https%3A%2F%2Fgithub.com%2Fvercel%2Fnext.js')
  await expect(page.locator('#detail-title')).toHaveText('Regular Expression Denial of Service in uglify-js')
  await expect(page.locator('.detail-label').first()).toContainText('vercel/next.js')
    await expect(page.locator('.detail-cvss')).toContainText('7.5')
    await expect(page.locator('.detail-cvss')).toContainText('高')
    await expect(page.getByText('CVSS出典：', { exact: false })).toContainText('CVSS 3.0 基本値')
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveCount(0)
  expect(writes).toEqual([])
})

test('saved article remains readable on mobile', async ({ page, request }) => {
  const response = await request.get('/api/cves?limit=1')
  const result = await response.json() as FeedResult
  const article = result.items[0]!
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto('/#/article/' + encodeURIComponent(article.id))
  await expect(page.locator('#detail-title')).toBeVisible()
  await expect(page.locator('.feed-detail')).toContainText(article.summary)
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.screenshot({ path: 'test-results/live-mobile.png', fullPage: true })
})
