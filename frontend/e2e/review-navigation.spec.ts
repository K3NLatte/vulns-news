import { test, expect } from '@playwright/test'

test('browser back and forward restore each entry including article and detail scroll positions', async ({ page }) => {
  await page.goto('/#/feed')
  const row = page.locator('#article-demo-008')
  await row.click()
  const y = await page.evaluate(() => scrollY)
  const body = page.locator('.detail-content')
  await body.evaluate((element) => {
    element.scrollTop = 220
  })
  const inner = await body.evaluate((element) => element.scrollTop)
  await page.locator('.feed-detail').getByRole('link', { name: 'ページで開く', exact: true }).click()
  await expect(page).toHaveURL(/article\/demo-008/)
  await page.evaluate(() => scrollTo(0, 450))
  await expect.poll(() => page.evaluate(() => scrollY)).toBe(450)
  await page.goBack()
  await expect(row).toBeFocused()
  await expect.poll(() => page.evaluate(() => scrollY)).toBeCloseTo(y, 0)
  await expect.poll(() => body.evaluate((element) => element.scrollTop)).toBeCloseTo(inner, 0)
  await page.goForward()
  await expect(page).toHaveURL(/article\/demo-008/)
  await expect.poll(() => page.evaluate(() => scrollY)).toBe(450)
  await page.goBack()
  await expect(row).toBeFocused()
  await expect.poll(() => page.evaluate(() => scrollY)).toBeCloseTo(y, 0)
})

test('IME composition leaves results in place and commits only the completed search', async ({ page }) => {
  await page.goto('/#/feed')
  const rows = page.locator('.feed-list > li')
  await expect(rows).toHaveCount(12)
  const input = page.getByLabel('記事を検索')
  await input.focus()
  await input.dispatchEvent('compositionstart', { data: '' })
  await input.evaluate((element) => {
    const input = element as HTMLInputElement
    input.value = '一致しない変換中'
    input.dispatchEvent(new InputEvent('input', { data: input.value, isComposing: true, bubbles: true }))
  })
  await page.waitForTimeout(300)
  await expect(rows).toHaveCount(12)
  await input.evaluate((element) => {
    ;(element as HTMLInputElement).value = 'SampleView'
  })
  await input.dispatchEvent('compositionend', { data: 'SampleView' })
  await expect(rows).toHaveCount(1)
  await expect(input).toBeFocused()
})

test('invalid locations show a recoverable 404 and MVP redirects do not trap browser history', async ({ page }) => {
  await page.goto('/#/not-a-page')
  await expect(page.getByRole('heading', { name: 'ページが見つかりません' })).toBeVisible()
  await page.getByRole('link', { name: 'フィードに戻る' }).click()
  await expect(page.locator('.feed-list')).toBeVisible()
  await page.goto('/?view=mvp#/feed')
  await page.getByRole('link', { name: 'リポジトリに関連', exact: true }).click()
  await page.evaluate(() => {
    location.hash = '#/settings'
  })
  await expect(page).toHaveURL(/#\/feed$/)
  await page.goBack()
  await expect(page).toHaveURL(/#\/repositories$/)
})

test('IDs still work without secure-context randomUUID', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: undefined })
  })
  await page.goto('/#/settings')
  await page.getByLabel('GitHubリポジトリのURL').fill('https://github.com/example/frontend')
  await page.getByRole('button', { name: '追加', exact: true }).click()
  await expect(page.getByRole('button', { name: /example\/frontend/ }).first()).toBeVisible()
  await page
    .getByRole('navigation', { name: 'メインメニュー' })
    .getByRole('button', { name: 'ログイン', exact: true })
    .click()
  await page.getByLabel('表示名', { exact: true }).fill('portable-user')
  await page.getByRole('dialog').getByRole('button', { name: 'ログイン', exact: true }).click()
  await expect(page.getByRole('dialog')).not.toBeVisible()
  await page.getByRole('link', { name: '脆弱性を分析', exact: true }).click()
  await page.getByLabel('CVE・GHSA・アドバイザリURL').fill('CVE-2026-999999')
  await page.getByRole('button', { name: '解析する', exact: true }).click()
  await expect(page.locator('.request-entry')).toContainText('CVE-2026-999999')
})

test('unexpected component exceptions show a safe recovery screen', async ({ page }) => {
  await page.route('**/src/components/AppHeader.vue*', (route) =>
    route.fulfill({
      contentType: 'application/javascript',
      body: 'export default { setup() { throw new Error("private-token-must-not-render") } }',
    }),
  )
  await page.goto('/#/feed')
  await expect(page.getByRole('heading', { name: '画面を表示できませんでした' })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('private-token-must-not-render')
  await page.unroute('**/src/components/AppHeader.vue*')
  await page.getByRole('button', { name: '再読み込み', exact: true }).click()
  await expect(page.locator('.feed-list')).toBeVisible()
})

test('long but valid identifiers remain readable at mobile widths', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto('/#/analyze')
  const cve = 'CVE-2026-' + '7'.repeat(600)
  await page.getByLabel('CVE・GHSA・アドバイザリURL').fill(cve)
  await page.getByRole('button', { name: '解析する', exact: true }).click()
  await expect(page.locator('.request-entry h3')).toHaveText(cve)
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test('new report notification does not move the feed or insert articles until requested', async ({ page }) => {
  for (const width of [1440, 320]) {
    await page.setViewportSize({ width, height: 1000 })
    const start = new Date('2026-09-25T04:00:00.000Z')
    await page.clock.setFixedTime(start)
    await page.goto('/#/feed')
    await page.evaluate(() => sessionStorage.clear())
    await page.reload()
    await expect(page.locator('.feed-list > li')).toHaveCount(12)
    const top = await page.locator('.feed-workspace').evaluate((element) => element.getBoundingClientRect().top)
    await page.clock.setFixedTime(new Date(start.getTime() + 31000))
    await expect(page.getByRole('button', { name: '新着 1件を表示', exact: true })).toBeVisible()
    await expect(page.locator('.feed-list > li')).toHaveCount(12)
    expect(await page.locator('.feed-workspace').evaluate((element) => element.getBoundingClientRect().top)).toBe(top)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  }
})
