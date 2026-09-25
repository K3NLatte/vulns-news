import { test, expect, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

async function article(page: Page, id = 'demo-001') {
  await page.goto('/#/article/' + id)
  await expect(page.locator('#detail-title')).toBeVisible()
}

async function noOverflow(page: Page) {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
}

test('manual share occupies document space and only handles Escape inside its own panel', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'share', { configurable: true, value: undefined })
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async () => {
          throw new Error('denied')
        },
      },
    })
  })
  await article(page)
  const share = page.getByRole('button', { name: '共有', exact: true })
  await share.click()
  const field = page.getByLabel('共有URL', { exact: true })
  await expect(field).toBeFocused()
  expect(await page.locator('.manual-copy').evaluate((el) => getComputedStyle(el).position)).toBe('static')
  const comment = page.getByLabel('コメントを追加', { exact: true })
  await comment.fill('共有パネルを開いたまま入力')
  await page.keyboard.press('Escape')
  await expect(comment).toBeFocused()
  await expect(field).toBeVisible()
  await page
    .getByRole('navigation', { name: 'メインメニュー' })
    .getByRole('button', { name: 'ログイン', exact: true })
    .click()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).not.toBeVisible()
  await expect(field).toBeVisible()
  await field.focus()
  await page.keyboard.press('Escape')
  await expect(share).toBeFocused()
  await expect(field).toHaveCount(0)
})

test('clipboard and reanalysis keep the originating button focused while busy', async ({ page }) => {
  await page.addInitScript(() => {
    const state = window as unknown as { finishCopy?: () => void }
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: () =>
          new Promise<void>((resolve) => {
            state.finishCopy = resolve
          }),
      },
    })
  })
  await article(page)
  const copy = page.getByRole('button', { name: '記事IDをコピー', exact: true })
  await copy.focus()
  await page.keyboard.press('Enter')
  await expect(copy).toHaveAttribute('aria-busy', 'true')
  await expect(copy).toBeFocused()
  await page.evaluate(() => (window as unknown as { finishCopy?: () => void }).finishCopy?.())
  await expect(copy).toHaveAttribute('aria-busy', 'false')
  await expect(copy).toBeFocused()
  const reanalyze = page.getByRole('button', { name: '再分析を依頼', exact: true })
  await reanalyze.focus()
  await page.keyboard.press('Enter')
  await expect(reanalyze).toHaveAttribute('aria-busy', 'true')
  await expect(reanalyze).toBeFocused()
})

test('comment drafts survive route changes and deletion requires confirmation with focus recovery', async ({
  page,
}) => {
  await article(page)
  const input = page.getByLabel('コメントを追加', { exact: true })
  await input.fill('調査中の下書き')
  await page.getByRole('link', { name: '設定', exact: true }).click()
  await page.goBack()
  await expect(input).toHaveValue('調査中の下書き')
  await page.getByRole('button', { name: 'コメントを追加', exact: true }).click()
  await expect(page.locator('.comment-body')).toHaveText('調査中の下書き')
  await expect(input).toHaveValue('')
  const remove = page.getByRole('button', { name: /^削除：調査中の下書き/ })
  await remove.click()
  await expect(page.getByRole('button', { name: 'キャンセル', exact: true })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(remove).toBeFocused()
  await expect(page.locator('.comment-body')).toHaveCount(1)
  await remove.click()
  await page.getByRole('button', { name: '削除する', exact: true }).click()
  await expect(page.locator('.comment-body')).toHaveCount(0)
  await expect(input).toBeFocused()
})

test('article hierarchy, unassessed CVSS and visible source hosts are accurate', async ({ page }) => {
  await article(page, 'demo-012')
  await expect(page.locator('.detail-cvss')).toContainText('未評価')
  await expect(page.locator('.detail-cvss')).not.toContainText('低')
  await expect(page.locator('.source-host').first()).toContainText('cwe.mitre.org')
  const results = await new AxeBuilder({ page }).withRules(['heading-order', 'label-content-name-mismatch']).analyze()
  expect(results.violations).toEqual([])
  await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
  await page.getByLabel('CVSS重要度').selectOption('unknown')
  await expect(page.locator('#article-demo-012')).toBeVisible()
  await page.getByLabel('CVSS重要度').selectOption('low')
  await expect(page.locator('#article-demo-012')).toHaveCount(0)
})

test('selection remains distinguishable in forced colors and mobile avoids false selected rows', async ({ page }) => {
  await page.goto('/#/feed')
  const row = page.locator('#article-demo-002')
  await row.click()
  await expect(row).toBeFocused()
  await page.emulateMedia({ forcedColors: 'active' })
  const selected = page.locator('.feed-list > .is-selected')
  const outline = await selected.evaluate((el) => ({
    width: getComputedStyle(el).outlineWidth,
    style: getComputedStyle(el).outlineStyle,
  }))
  expect(outline.width).toBe('2px')
  expect(outline.style).toBe('solid')
  await page.getByRole('button', { name: '詳細を読む', exact: true }).click()
  await expect(page.locator('#detail-title')).toBeFocused()
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.locator('.feed-list > .is-selected')).toHaveCount(0)
  await expect(page.locator('.feed-item[aria-current]')).toHaveCount(0)
  await noOverflow(page)
})

test('browser default text size scales root and long bodies wrap at narrow widths', async ({ page, browserName }) => {
  test.skip(
    browserName !== 'chromium',
    'Browser default font size is controlled with Chromium CDP; Firefox is covered by the shared responsive tests.',
  )
  const session = await page.context().newCDPSession(page)
  await session.send('Page.setFontSizes', { fontSizes: { standard: 32, fixed: 26 } })
  await page.setViewportSize({ width: 1024, height: 768 })
  await article(page)
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).fontSize)).toBe('32px')
  await noOverflow(page)
  await session.send('Page.setFontSizes', { fontSizes: { standard: 16, fixed: 13 } })
  await page.setViewportSize({ width: 390, height: 844 })
  const input = page.getByLabel('コメントを追加', { exact: true })
  await input.fill('a'.repeat(1200))
  await page.getByRole('button', { name: 'コメントを追加', exact: true }).click()
  await expect(page.locator('.comment-body')).toHaveText('a'.repeat(1200))
  await noOverflow(page)
})

test('invalid form input gets a local actionable error and clears during correction', async ({ page }) => {
  await page.goto('/#/repositories')
  const repository = page.getByLabel('公開リポジトリ', { exact: true })
  await repository.fill('   ')
  await page.getByRole('button', { name: '読み込む', exact: true }).click()
  await expect(repository).toHaveAttribute('aria-invalid', 'true')
  await expect(repository).toBeFocused()
  await repository.fill('https://github.com/Example/Frontend')
  await expect(repository).toHaveAttribute('aria-invalid', 'false')
  await page.getByRole('button', { name: '読み込む', exact: true }).click()
  await expect(page.getByLabel('表示するリポジトリ')).toContainText('Example/Frontend')
  await page
    .getByRole('navigation', { name: 'メインメニュー' })
    .getByRole('button', { name: 'ログイン', exact: true })
    .click()
  await page.getByRole('dialog').getByRole('button', { name: 'ログイン', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('表示名を入力')
  await page.getByLabel('表示名', { exact: true }).fill('🐱'.repeat(40))
  await page.getByRole('dialog').getByRole('button', { name: 'ログイン', exact: true }).click()
  await expect(page.getByRole('dialog')).not.toBeVisible()
})

test('repository drafts survive route changes and stay isolated between guest and profiles', async ({ page }) => {
  const menu = page.getByRole('navigation', { name: 'メインメニュー' })
  const settingsInput = page.getByLabel('GitHubリポジトリのURL', { exact: true })
  const repositoryInput = page.getByLabel('公開リポジトリ', { exact: true })
  async function login(name: string) {
    await menu.getByRole('button', { name: 'ログイン', exact: true }).click()
    await page.getByLabel('表示名', { exact: true }).fill(name)
    await page.getByRole('dialog').getByRole('button', { name: 'ログイン', exact: true }).click()
    await expect(page.getByRole('dialog')).not.toBeVisible()
  }
  async function logout() {
    await menu.getByRole('button', { name: /のアカウントを開く$/ }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'ログアウト', exact: true }).click()
    await expect(page.getByRole('dialog')).not.toBeVisible()
  }
  async function feed() {
    await page.getByRole('link', { name: 'vulns/news フィード', exact: true }).click()
    await expect(page.locator('.feed-list')).toBeVisible()
  }

  await page.goto('/#/repositories')
  await repositoryInput.fill('https://github.com/Guest/UnfinishedFeed')
  await feed()
  await page.getByRole('link', { name: 'リポジトリに関連', exact: true }).click()
  await expect(repositoryInput).toHaveValue('https://github.com/Guest/UnfinishedFeed')
  await menu.getByRole('link', { name: '設定', exact: true }).click()
  await settingsInput.fill('https://github.com/Guest/UnfinishedSettings')
  await feed()
  await menu.getByRole('link', { name: '設定', exact: true }).click()
  await expect(settingsInput).toHaveValue('https://github.com/Guest/UnfinishedSettings')

  await login('draft-alice')
  await expect(settingsInput).toHaveValue('')
  await settingsInput.fill('https://github.com/Alice/UnfinishedSettings')
  await logout()
  await expect(settingsInput).toHaveValue('https://github.com/Guest/UnfinishedSettings')
  await login('draft-bob')
  await expect(settingsInput).toHaveValue('')
  await settingsInput.fill('https://github.com/Bob/UnfinishedSettings')
  await logout()
  await login('draft-alice')
  await expect(settingsInput).toHaveValue('https://github.com/Alice/UnfinishedSettings')

  await feed()
  await page.getByRole('link', { name: 'リポジトリに関連', exact: true }).click()
  await expect(repositoryInput).toHaveValue('')
  await logout()
  await expect(repositoryInput).toHaveValue('https://github.com/Guest/UnfinishedFeed')
})
