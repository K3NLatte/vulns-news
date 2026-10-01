import { mkdir, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { test, expect } from '@playwright/test'
import type { FeedItem, FeedResult } from '../src/types/feed'

// Opt-in capture of the imported Next.js snapshot, using the real production UI.
test('capture saved analysis for presentation slides', async ({ page, request }) => {
  test.skip(process.env.NEWS_CAPTURE_SLIDES !== '1', 'set NEWS_CAPTURE_SLIDES=1 to capture slides')
  const output = resolve('../.local/slides')
  await mkdir(output, { recursive: true })
  await page.setViewportSize({ width: 1600, height: 900 })
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  const repository = 'https://github.com/vercel/next.js'
  const articleID = 'CVE-2015-8858'

  const writes: string[] = []
  page.on('request', req => { if (req.method() !== 'GET') writes.push(req.method() + ' ' + req.url()) })
  await page.goto('/')
  await expect(page.getByRole('heading', { name: '保存済み解析結果' })).toBeVisible()
  await expect(page.getByText('読み取り専用：', { exact: false })).toBeVisible()
  await page.evaluate(() => document.fonts.ready)
  await page.screenshot({ path: resolve(output, '00-saved-analyses.png'), animations: 'disabled' })
  const catalog = await (await request.get('/api/analyses')).json()
  const ids = catalog.items.find((item: { url: string }) => item.url === repository).job as { repository_id: string; job_id: string }
  await page.getByRole('button', { name: 'vercel/next.js — 結果を開く', exact: true }).click()
  const feedResponse = await request.get(`/api/repositories/${ids.repository_id}/feed`)
  expect(feedResponse.ok()).toBeTruthy()
  const feed = await feedResponse.json() as FeedResult
  expect(feed.total).toBe(582)
  expect(feed.scanStatus).toBe('incomplete')
  expect(feed.repositoryCommit).toBe('0423222b7eb3a1373b5bff4c939fd69858928993')
  await expect(page.getByRole('list', { name: '脆弱性記事', exact: true }).getByRole('listitem')).toHaveCount(582)
  await expect(page.getByRole('button', { name: /^分析済み/ })).toContainText('355')
  await expect(page.getByRole('button', { name: /^未確定/ })).toContainText('227')
  await expect(page.getByText('スキャン範囲に未確認の項目があります。', { exact: false })).toBeVisible()
  await expect(page.locator('#detail-title')).toBeVisible()
  await page.evaluate(() => document.fonts.ready)
  await page.screenshot({ path: resolve(output, '01-repository-overview.png'), animations: 'disabled' })

  const detailResponse = await request.get(`/api/repositories/${ids.repository_id}/feed/${articleID}`)
  expect(detailResponse.ok()).toBeTruthy()
  const article = await detailResponse.json() as FeedItem
  expect(article.repositoryAnalysis).toBe('analyzed')
  expect(article.relevance?.packageName).toBe('uglify-js')
  expect(article.relevance?.installedVersion).toBe('2.4.24')
    expect(article.title).toBe('Regular Expression Denial of Service in uglify-js')
  await page.goto('/#/article/' + articleID + '?repository=' + encodeURIComponent(repository))
  await expect(page.locator('#detail-title')).toBeVisible()
  await expect(page.locator('.detail-summary')).toHaveText(article.summary)
  await expect(page.locator('.repository-impact-facts')).toContainText('uglify-js@2.4.24')
  await page.evaluate(() => { window.scrollTo(0, 0) })
  await page.screenshot({ path: resolve(output, '02-article-detail.png'), animations: 'disabled' })

  await page.getByText('根拠を読む', { exact: true }).click()
  await page.getByRole('heading', { name: '解析結果に基づく対応案', exact: true }).scrollIntoViewIfNeeded()
  await page.screenshot({ path: resolve(output, '03-analysis-evidence.png'), animations: 'disabled' })
  await page.screenshot({ path: resolve(output, '04-article-full.png'), fullPage: true, animations: 'disabled' })
  await writeFile(resolve(output, 'capture.json'), JSON.stringify({
    repository, repositoryCommit: feed.repositoryCommit, scanStatus: feed.scanStatus,
    total: feed.total, analyzed: 355, screeningOnly: 227, excluded: 9,
    sourceArchive: 'analysis-results.zip', sourceAnalysis: 'analysis-results.json', sourceScan: 'analysis-scan-state.json',
    article, viewport: { width: 1600, height: 900 },
  }, null, 2))
  expect(errors).toEqual([])
  expect(writes).toEqual([])
})
