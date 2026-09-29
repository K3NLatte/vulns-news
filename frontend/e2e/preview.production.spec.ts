import { expect, test } from '@playwright/test'

test('本番はURLのモック指定を無視し、APIの結果と公開リポジトリフォームを表示する', async ({ page }) => {
  const errors: string[] = []
  const calls: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  page.on('request', request => {
    if (new URL(request.url()).pathname.startsWith('/api/')) calls.push(request.method() + ' ' + new URL(request.url()).pathname)
  })
  for (const scenario of ['empty', 'loading', 'error']) {
    await page.goto(`/?analysis=failed&scenario=${scenario}&view=full&source=local#/feed`)
    await expect(page.getByRole('list', { name: '脆弱性記事', exact: true }).getByRole('listitem')).toHaveCount(12)
    await expect(page.locator('#detail-title')).toBeVisible()
    await expect(page.locator('a[href="#/analyze"], a[href="#/saved"], a[href="#/settings"], .save-button')).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'ログイン', exact: true })).toHaveCount(0)
  }
  expect(calls.filter(call => call === 'GET /api/cves')).toHaveLength(3)
  await page.goto('/?analysis=completed&scenario=empty&view=full#/repositories')
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toBeVisible()
  await expect(page.getByLabel('リポジトリの解析状況')).toHaveCount(0)
  await expect(page.getByRole('list', { name: '脆弱性記事', exact: true })).toHaveCount(0)
  expect(calls.filter(call => call === 'POST /api/repositories')).toHaveLength(0)
  expect(errors).toEqual([])
})

test('本番のAPI障害をブラウザ内のサンプルで隠さない', async ({ page }) => {
  await page.route('**/api/cves?*', route => route.fulfill({ status: 503, body: 'SECRET_PROXY_CONFIG' }))
  await page.goto('/?scenario=ready&view=mvp&source=local#/feed')
  await expect(page.getByRole('alert')).toContainText('HTTP 503')
  await expect(page.getByRole('list', { name: '脆弱性記事', exact: true })).toHaveCount(0)
  await expect(page.locator('body')).not.toContainText('SECRET_PROXY_CONFIG')
  await page.unroute('**/api/cves?*')
  await page.getByRole('button', { name: '再試行', exact: true }).click()
  await expect(page.getByRole('list', { name: '脆弱性記事', exact: true }).getByRole('listitem')).toHaveCount(12)
})
