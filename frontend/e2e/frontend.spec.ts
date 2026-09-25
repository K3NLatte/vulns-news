import { test as base, expect, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

// Every scenario must finish without uncaught application errors.
const test = base.extend<{ checkErrors: void }>({
  checkErrors: [async ({ page }, use) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    await use()
    expect(errors).toEqual([])
  }, { auto: true }],
})
const articles = (page: Page) => page.getByRole('list', { name: '脆弱性記事', exact: true })
async function ready(page: Page, route = '/#/feed') {
  await page.goto(route)
  await expect(articles(page)).toBeVisible()
}
async function login(page: Page, name: string) {
  await page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name: 'ログイン', exact: true }).click()
  await page.getByLabel('表示名', { exact: true }).fill(name)
  await page.getByRole('dialog').getByRole('button', { name: 'ログイン', exact: true }).click()
  await expect(page.getByRole('dialog')).not.toBeVisible()
}
async function submit(page: Page, input: string) {
  await page.getByLabel('CVE・GHSA・アドバイザリURL').fill(input)
  await page.getByRole('button', { name: '解析する', exact: true }).click()
}
async function noOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
}

test('search, filters and keyboard clearing recover the feed', async ({ page }) => {
  await ready(page)
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await expect(page.getByLabel('並び順').getByRole('option', { name: '関連度が高い順' })).toHaveCount(0)
  await page.getByLabel('記事を検索').fill('ｓａｍｐｌｅｖｉｅｗ')
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  const clear = page.getByRole('button', { name: '検索をクリア' })
  await clear.focus(); await page.keyboard.press('Enter')
  await expect(page.getByLabel('記事を検索')).toBeFocused()
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await page.getByLabel('CVSS重要度').selectOption('high')
  await expect(articles(page).getByRole('listitem')).toHaveCount(5)
  await page.getByLabel('記事を検索').fill('絶対に一致しない検索語')
  await expect(page.getByRole('heading', { name: '該当する記事がありません' })).toBeVisible()
  await page.getByRole('button', { name: '条件を解除', exact: true }).first().click()
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
})

test('Indeed-style pane preserves the list position and article back navigation', async ({ page }) => {
  await ready(page)
  const row = page.locator('#article-demo-008')
  await row.scrollIntoViewIfNeeded()
  const before = await page.evaluate(() => scrollY)
  await row.click()
  await expect(row).toBeFocused()
  expect(Math.abs(await page.evaluate(() => scrollY) - before)).toBeLessThan(3)
  const dimensions = await page.locator('.list-panel').evaluate(element => ({ height: element.clientHeight, overflow: getComputedStyle(element).overflowY }))
  expect(dimensions.height).toBeGreaterThan(1000)
  expect(dimensions.overflow).not.toBe('auto')
  await page.locator('.feed-detail').getByRole('link', { name: 'ページで開く', exact: true }).click()
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await expect(page).toHaveTitle(/DEMO-2026-008/)
  await page.getByRole('button', { name: /一覧に戻る/ }).click()
  await expect(row).toBeFocused()
  expect(Math.abs(await page.evaluate(() => scrollY) - before)).toBeLessThan(3)
})

test('multiple repositories preserve canonical identity and enable relevance sorting', async ({ page }) => {
  await page.goto('/#/settings')
  const input = page.getByLabel('GitHubリポジトリのURL')
  await input.fill('https://github.com.evil.example/a/b')
  await page.getByRole('button', { name: '追加', exact: true }).click()
  await expect(input).toHaveAttribute('aria-invalid', 'true')
  for (const url of ['https://github.com/Example/Frontend', 'https://github.com/example/backend']) {
    await input.fill(url); await page.getByRole('button', { name: '追加', exact: true }).click()
  }
  await page.reload()
  await expect(page.getByRole('button', { name: /Example\/Frontend/ }).first()).toBeVisible()
  await input.fill('https://github.com/example/frontend')
  await page.getByRole('button', { name: '追加', exact: true }).click()
  await expect(page.getByText('このリポジトリは登録済みです。')).toBeVisible()
  await page.goto('/#/repositories')
  await expect(articles(page)).toBeVisible()
  await page.getByLabel('表示するリポジトリ').selectOption({ label: 'Example/Frontend' })
  await page.getByLabel('並び順').selectOption('relevance')
  await expect(articles(page).getByRole('button', { name: /DEMO-2026-003/ }).first()).toBeVisible()
  await page.getByRole('button', { name: '過去情報も検索', exact: true }).click()
  await expect(page.locator('.repository-history-status')).toContainText('検索済み')
  await expect(page.locator('#article-history-002')).toBeVisible()
  await page.locator('#article-history-002').click()
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  await expect(page.locator('.analysis-section')).toHaveCount(0)
})

test('comments stay text; deletion and profile dialog return keyboard focus', async ({ page }) => {
  await page.goto('/#/article/demo-001')
  const input = page.getByLabel('コメントを追加', { exact: true })
  const payload = '<img src=x onerror="window.__injected=1">'
  await input.fill(payload)
  await page.getByRole('button', { name: 'コメントを追加', exact: true }).click()
  await expect(page.locator('.comment-body')).toHaveText(payload)
  await expect(page.locator('.comment-body img')).toHaveCount(0)
  const name = '<svg onload=window.__injected=1>'
  await login(page, name)
  await expect(page.locator('.comment-author')).toHaveText(name)
  await page.reload()
  await expect(page.locator('.comment-author svg')).toHaveCount(0)
  await page.getByRole('button', { name: /^削除：/ }).focus()
  await page.keyboard.press('Enter')
  await page.getByRole('button', { name: '削除する', exact: true }).click()
  await expect(input).toBeFocused()
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).__injected)).toBeUndefined()
  const account = page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name: name + ' のアカウントを開く', exact: true })
  await account.click()
  await page.keyboard.press('Escape')
  await expect(account).toBeFocused()
})

test('saved submitted report survives a new session, unsave/resave, and stays out of guest state', async ({ page, browser }) => {
  await page.goto('/#/analyze')
  await login(page, 'reviewer')
  await submit(page, 'CVE-2026-12345')
  await expect(page.locator('.request-entry').first().locator('.state-completed')).toBeVisible()
  await page.locator('.request-entry').first().getByRole('link').click()
  await page.locator('.feed-detail').getByRole('button', { name: /^保存：/ }).click()
  await page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('link', { name: /保存済み/ }).click()
  await expect(articles(page)).toContainText('CVE-2026-12345')
  let state = await page.context().storageState()
  for (let round = 0; round < 2; round++) {
    const context = await browser.newContext({ storageState: state, baseURL: test.info().project.use.baseURL, viewport: { width: 1440, height: 1000 } })
    try {
      const fresh = await context.newPage()
      const errors: string[] = []
      fresh.on('pageerror', error => errors.push(error.message))
      await fresh.goto('/#/feed'); await login(fresh, 'reviewer')
      await fresh.goto('/#/saved')
      await expect(articles(fresh)).toContainText('CVE-2026-12345')
      await fresh.getByRole('link', { name: 'ページで開く：CVE-2026-12345' }).click()
      await expect(fresh.getByRole('heading', { level: 1 })).toContainText('CVE-2026-12345')
      await fresh.locator('.feed-detail').getByRole('button', { name: /^保存：/ }).click()
      await expect(fresh.getByRole('heading', { level: 1 })).toContainText('CVE-2026-12345')
      await fresh.locator('.feed-detail').getByRole('button', { name: /^保存：/ }).click()
      state = await context.storageState()
      await fresh.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name: 'reviewer' }).click()
      await fresh.getByRole('button', { name: 'ログアウト' }).click()
      await expect(fresh.getByRole('heading', { name: '記事が見つかりません' })).toBeVisible()
      expect(errors).toEqual([])
    } finally { await context.close() }
  }
})

test('analysis rejects unsafe input, deduplicates active requests and preserves cancellation on reload', async ({ page }) => {
  await page.goto('/#/analyze')
  await submit(page, 'javascript:alert(1)')
  await expect(page.locator('#analysis-input-error')).toBeVisible()
  await expect(page.getByLabel('CVE・GHSA・アドバイザリURL')).toBeFocused()
  await submit(page, 'CVE-2026-98765')
  await submit(page, 'cve-2026-98765')
  await expect(page.locator('.request-entry')).toHaveCount(1)
  await page.getByRole('button', { name: '中止：CVE-2026-98765' }).click()
  await expect(page.locator('.state-cancelled')).toBeVisible()
  await page.reload()
  await expect(page.locator('.state-cancelled')).toBeVisible()
  await expect(page.locator('.request-reports')).toHaveCount(0)
})

test('malformed history is ignored and new valid work remains possible', async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('vulns-news-report-lab-v2:guest', JSON.stringify({
      jobs: [{ kind: { toString: null }, key: 'CVE-2026-12345', createdAt: new Date().toISOString(), status: 'completed' }],
      publishedIds: ['constructor', '__proto__'], lifecycles: { constructor: {} },
    }))
  })
  await page.goto('/#/analyze')
  await submit(page, 'CVE-2026-23456')
  await expect(page.locator('.state-completed')).toBeVisible()
  await page.locator('.request-entry').first().getByRole('link').click()
  await expect(page.locator('.detail-cvss')).toContainText('未評価')
})

test('clipboard failure offers a selectable URL and restores focus on Escape', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'share', { value: undefined, configurable: true })
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async () => { throw new Error('denied') } }, configurable: true })
  })
  await ready(page)
  const button = page.getByRole('button', { name: '共有', exact: true })
  await button.click()
  await expect(page.getByLabel('共有URL')).toHaveValue(/#\/article\/demo-001$/)
  await expect(page.getByLabel('共有URL')).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(page.getByLabel('共有URL')).not.toBeVisible()
  await expect(button).toBeFocused()
})

test('storage denial keeps the current session usable and reports unsaved changes', async ({ page }) => {
  await page.addInitScript(() => {
    Storage.prototype.setItem = () => { throw new DOMException('denied', 'QuotaExceededError') }
  })
  await ready(page)
  await page.locator('.feed-list').getByRole('button', { name: '保存：DEMO-2026-001', exact: true }).click()
  await expect(page.locator('.feed-list').getByRole('button', { name: '保存：DEMO-2026-001', exact: true })).toHaveAttribute('aria-pressed', 'false')
  await expect(page.getByRole('alert').filter({ hasText: '保存できません' }).first()).toBeVisible()
})

for (const scenario of ['error', 'empty', 'loading']) {
  test('feed state: ' + scenario, async ({ page }) => {
    await page.goto('/?scenario=' + scenario + '#/feed')
    if (scenario === 'error') {
      await expect(page.getByRole('heading', { name: '読み込めませんでした' })).toBeVisible()
      await page.getByRole('button', { name: '再試行' }).click()
      await expect(articles(page)).toBeVisible()
    } else if (scenario === 'empty') {
      await expect(page.getByRole('heading', { name: '該当する記事がありません' })).toBeVisible()
    } else {
      await expect(page.getByText('読み込み中', { exact: true }).first()).toBeVisible()
      await expect(articles(page)).not.toBeVisible()
    }
  })
}

test('mobile, short viewport and 200 percent text retain readable content', async ({ page }) => {
  for (const viewport of [{ width: 320, height: 700 }, { width: 390, height: 844 }, { width: 1280, height: 480 }]) {
    await page.setViewportSize(viewport)
    await ready(page)
    await page.locator('#article-demo-006').click()
    await expect(page.locator('h1#detail-title')).toContainText('Markdownプレビュー')
    await noOverflow(page)
  }
  await page.setViewportSize({ width: 1024, height: 600 })
  await ready(page)
  await page.evaluate(() => { document.documentElement.style.fontSize = '32px' })
  await page.locator('#article-demo-006').click()
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await noOverflow(page)
})

test('MVP uses shared components and omits unselected full features', async ({ page }) => {
  await ready(page, '/?view=mvp#/feed')
  await expect(page.getByRole('navigation', { name: 'メインメニュー' })).toHaveCount(0)
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await page.goto('/?view=mvp#/analyze')
  await expect(page).toHaveURL(/#\/feed$/)
  await expect(articles(page)).toBeVisible()
})

test('WCAG automated checks cover main routes and the account dialog', async ({ page }) => {
  for (const route of ['feed', 'article/demo-006', 'settings', 'analyze', 'saved', 'repositories']) {
    await page.goto('/#/' + route)
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    if (route === 'feed') await expect(articles(page)).toBeVisible()
    if (route.startsWith('article')) await expect(page.locator('#detail-title')).toBeVisible()
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
    expect(results.violations, route + ': ' + JSON.stringify(results.violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.target) })))).toEqual([])
    if (route === 'feed') {
      await page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name: 'ログイン' }).click()
      const dialog = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
      expect(dialog.violations).toEqual([])
      await page.keyboard.press('Escape')
    }
  }
})

test('oversized CVE identifiers are rejected without creating a report', async ({ page }) => {
  await page.goto('/#/analyze')
  // Bypass the native length guard to exercise the application boundary too.
  await page.getByLabel('CVE・GHSA・アドバイザリURL').evaluate(element => element.removeAttribute('maxlength'))
  await submit(page, 'CVE-2026-' + '7'.repeat(2050))
  await expect(page.locator('#analysis-input-error')).toBeVisible()
  await expect(page.locator('.request-entry')).toHaveCount(0)
})

test('a stale profile tab cannot silently overwrite a newer saved list', async ({ page, context }) => {
  await ready(page); await login(page, 'concurrent-review')
  const second = await context.newPage()
  try {
    await ready(second)
    // New pages have their own sessionStorage and explicitly reopen the same local profile.
    await login(second, 'concurrent-review')
    await page.locator('.feed-list').getByRole('button', { name: '保存：DEMO-2026-001', exact: true }).click()
    await second.locator('.feed-list').getByRole('button', { name: '保存：DEMO-2026-002', exact: true }).click()
    await expect(second.getByRole('alert').filter({ hasText: '別のタブ' }).first()).toBeVisible()
    await page.reload()
    await expect(page.locator('.feed-list').getByRole('button', { name: '保存：DEMO-2026-001', exact: true })).toHaveAttribute('aria-pressed', 'true')
    await expect(page.locator('.feed-list').getByRole('button', { name: '保存：DEMO-2026-002', exact: true })).toBeVisible()
  } finally { await second.close() }
})
