import { expect, test as base, type Page } from '@playwright/test'

const test = base.extend<{ checkErrors: void }>({
  checkErrors: [async ({ page }, use) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    await use()
    expect(errors).toEqual([])
  }, { auto: true }],
})
const rows = (page: Page) => page.getByRole('list', { name: '脆弱性記事', exact: true }).getByRole('listitem')
async function login(page: Page, name: string) {
  await page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name: 'ログイン', exact: true }).click()
  await page.getByLabel('表示名', { exact: true }).fill(name)
  await page.getByRole('dialog').getByRole('button', { name: 'ログイン', exact: true }).click()
  await expect(page.getByRole('dialog')).not.toBeVisible()
}
async function logout(page: Page, name: string) {
  await page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name, exact: true }).click()
  await page.getByRole('button', { name: 'ログアウト', exact: true }).click()
}
async function registerRepository(page: Page) {
  await page.goto('/#/settings')
  await page.getByLabel('GitHubリポジトリのURL').fill('https://github.com/example/backend')
  await page.getByRole('button', { name: '追加', exact: true }).click()
}

test('unrelated and pending repository articles expose no definitive assessment or review editor', async ({ page }) => {
  await registerRepository(page)
  for (const id of ['demo-001', 'demo-005']) {
    await page.goto(`/#/article/${id}?repository=https%3A%2F%2Fgithub.com%2Fexample%2Fbackend`)
    await expect(page.locator('#detail-title')).toBeVisible()
    await expect(page.locator('.pending-analysis-note')).toBeVisible()
    await expect(page.locator('.relevance-section')).toHaveCount(0)
    await expect(page.getByLabel('このリポジトリでの対応', { exact: true })).toHaveCount(0)
  }
  await page.goto('/#/article/demo-002?repository=https%3A%2F%2Fgithub.com%2Fexample%2Fbackend')
  await expect(page.locator('.relevance-section')).toContainText('95 / 100')
  await expect(page.getByLabel('このリポジトリでの対応', { exact: true })).toBeVisible()
  await page.goBack()
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  await expect(page.getByLabel('このリポジトリでの対応', { exact: true })).toHaveCount(0)
  await page.goto('/#/analyze')
  await expect(page.locator('.request-entry')).toHaveCount(0)
})

test('relevance sort puts all pending results behind evaluated results', async ({ page }) => {
  await registerRepository(page)
  await page.goto('/#/repositories')
  await page.getByLabel('並び順').selectOption('relevance')
  await expect(rows(page)).toHaveCount(5)
  const ids = await page.locator('.feed-item').evaluateAll(elements => elements.map(element => element.id))
  expect(ids).toEqual(['article-demo-002', 'article-demo-004', 'article-demo-007', 'article-demo-005', 'article-demo-009'])
  await expect(page.locator('#article-demo-005 .relevance-tag')).toHaveCount(0)
})

test('profile switching isolates request history and submitted article access', async ({ page }) => {
  await page.goto('/#/analyze')
  await login(page, 'alice')
  await page.getByLabel('CVE・GHSA・アドバイザリURL').fill('https://vendor.example/advisory/42?session=alice-private')
  await page.getByRole('button', { name: '解析する', exact: true }).click()
  await expect(page.locator('.request-entry')).toHaveCount(1)
  const reportLink = page.locator('.request-entry').getByRole('link')
  await expect(reportLink).toBeVisible()
  const reportPath = await reportLink.getAttribute('href')
  expect(reportPath).toMatch(/^#\/article\//)
  await logout(page, 'alice')
  await expect(page.locator('.request-entry')).toHaveCount(0)
  await login(page, 'bob')
  await expect(page.locator('.request-entry')).toHaveCount(0)
  await expect(page.locator('main')).not.toContainText('alice-private')
  await page.goto('/' + reportPath)
  await expect(page.getByRole('heading', { name: '記事が見つかりません' })).toBeVisible()
  await page.goto('/#/analyze')
  await page.reload()
  await expect(page.locator('.request-entry')).toHaveCount(0)
  await logout(page, 'bob')
  await login(page, 'alice')
  await expect(page.locator('.request-entry')).toHaveCount(1)
  await page.locator('.request-entry').getByRole('link').click()
  await expect(page.locator('a[href="https://vendor.example/advisory/42?session=alice-private"]')).toBeVisible()
})

test('repository search starts only on request and reports capacity rejection at the action', async ({ page }) => {
  await registerRepository(page)
  await page.goto('/#/analyze')
  await page.clock.setFixedTime(new Date())
  for (let index = 0; index < 5; index++) {
    await page.getByLabel('CVE・GHSA・アドバイザリURL').fill(`CVE-2026-${81000 + index}`)
    await page.getByRole('button', { name: '解析する', exact: true }).click()
  }
  await page.goto('/#/repositories')
  await expect(page.locator('.repository-history-status')).toContainText('過去情報は未検索')
  await page.getByRole('button', { name: '過去情報も検索', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('同時に依頼できるのは5件まで')
  await expect(page.locator('.repository-history-status')).not.toContainText('検索中')
})

test('comment rejection remains visible after a logged-in workspace synchronization', async ({ page }) => {
  await page.goto('/#/article/demo-001')
  await login(page, 'commenter')
  const input = page.getByLabel('コメントを追加', { exact: true })
  // Firefox's keyboard insertion normalizes form-feed; inject the raw value at the input boundary.
  await input.evaluate(element => {
    (element as HTMLTextAreaElement).value = 'before\u000cafter'
    element.dispatchEvent(new Event('input', { bubbles: true }))
  })
  await expect(input).toHaveValue('before\u000cafter')
  await page.getByRole('button', { name: 'コメントを追加', exact: true }).click()
  await expect(input).toHaveAttribute('aria-invalid', 'true')
  await expect(page.locator('.comment-thread [role="alert"]')).toBeVisible()
  await expect(input).toHaveValue('before\u000cafter')
  await expect(page.locator('.comment-body')).toHaveCount(0)
})

test('IME conversion does not filter until composition ends', async ({ page }) => {
  await page.goto('/#/feed')
  await expect(rows(page)).toHaveCount(12)
  const input = page.getByLabel('記事を検索')
  await input.focus()
  await input.dispatchEvent('compositionstart')
  await input.evaluate(element => { (element as HTMLInputElement).value = 'さ' })
  await input.dispatchEvent('input', { isComposing: true, inputType: 'insertCompositionText', data: 'さ' })
  // Longer than the search debounce, while the IME still owns the value.
  await page.waitForTimeout(350)
  await expect(rows(page)).toHaveCount(12)
  await input.evaluate(element => { (element as HTMLInputElement).value = 'sampleview' })
  await input.dispatchEvent('compositionend', { data: 'sampleview' })
  await expect(rows(page)).toHaveCount(1)
})

test('Escape from a login dialog does not close the share panel behind it', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'share', { value: undefined, configurable: true })
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async () => { throw new Error('denied') } }, configurable: true })
  })
  await page.goto('/#/article/demo-001')
  await page.getByRole('button', { name: '共有', exact: true }).click()
  await expect(page.getByLabel('共有URL')).toBeFocused()
  await page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name: 'ログイン', exact: true }).click()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).not.toBeVisible()
  await expect(page.getByLabel('共有URL')).toBeVisible()
  await page.getByLabel('共有URL').focus()
  await page.keyboard.press('Escape')
  await expect(page.getByLabel('共有URL')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '共有', exact: true })).toBeFocused()
})
