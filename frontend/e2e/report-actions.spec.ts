import { test as base, expect } from '@playwright/test'

const test = base.extend<{ checkErrors: void }>({
  checkErrors: [async ({ page }, use) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    await use()
    expect(errors).toEqual([])
  }, { auto: true }],
})

test('manual analysis preserves expiry until tracking is explicitly renewed', async ({ page }) => {
  const expiredAt = new Date('2026-10-25T03:00:00.000Z')
  await page.clock.setFixedTime(expiredAt)
  await page.goto('/#/article/demo-006')
  const tracking = page.getByRole('region', { name: 'レポートの更新と追跡' })
  const lastAnalysis = tracking.locator('dl > div').filter({ hasText: '最終分析' }).locator('dd')
  const deadline = tracking.locator('dl > div').filter({ hasText: '追跡期限' }).locator('dd')
  await expect(tracking.getByText('追跡期間終了', { exact: true })).toBeVisible()
  await expect(lastAnalysis).toContainText('第1版')
  const previousDeadline = await deadline.innerText()

  await tracking.getByRole('button', { name: '再分析を依頼', exact: true }).click()
  await expect(tracking.getByRole('button', { name: '再分析を依頼', exact: true })).toHaveAttribute('aria-disabled', 'true')
  // Date is fixed independently of real timers; advance it past the local job's completion.
  await page.clock.setFixedTime(new Date(expiredAt.getTime() + 7000))
  await expect(lastAnalysis).toContainText('第2版')
  await expect(deadline).toHaveText(previousDeadline)
  await expect(tracking.getByText('追跡期間終了', { exact: true })).toBeVisible()

  await tracking.getByRole('button', { name: '7日間追跡を再開', exact: true }).click()
  await expect(tracking.getByText('自動追跡中', { exact: true })).toBeVisible()
  await expect(lastAnalysis).toContainText('第2版')
  await expect(deadline).not.toHaveText(previousDeadline)
  await expect(tracking.getByText('次回確認', { exact: true })).toBeVisible()
  await page.reload()
  await expect(tracking.getByText('自動追跡中', { exact: true })).toBeVisible()
  await expect(lastAnalysis).toContainText('第2版')
})

test('repository review decisions survive expansion and reload without leaking into the general article', async ({ page }) => {
  await page.goto('/#/settings')
  await page.getByLabel('GitHubリポジトリのURL').fill('https://github.com/example/frontend')
  await page.getByRole('button', { name: '追加', exact: true }).click()
  await page.goto('/#/repositories')
  await page.locator('#article-demo-003').click()
  const review = page.getByLabel('このリポジトリでの対応', { exact: true })
  await review.selectOption('resolved')
  await page.locator('.feed-detail').getByRole('link', { name: 'ページで開く', exact: true }).click()
  await expect(review).toHaveValue('resolved')
  const repositoryArticleUrl = page.url()
  await page.reload()
  await expect(review).toHaveValue('resolved')

  await review.selectOption('not-affected')
  await page.reload()
  await expect(review).toHaveValue('not-affected')
  await page.goto('/#/article/demo-003')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await expect(review).toHaveCount(0)
  await page.goto(repositoryArticleUrl)
  await expect(review).toHaveValue('not-affected')
})

test('a failed second ID copy clears the previous success message', async ({ page }) => {
  await page.addInitScript(() => {
    let attempts = 0
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: async () => {
        attempts += 1
        if (attempts > 1) throw new DOMException('denied', 'NotAllowedError')
      } },
    })
  })
  await page.goto('/#/article/demo-001')
  const copy = page.getByRole('button', { name: '記事IDをコピー', exact: true })
  const feedback = page.locator('.copy-feedback')
  await copy.click()
  await expect(feedback).toHaveText('コピーしました')
  await copy.click()
  await expect(page.getByRole('alert').filter({ hasText: 'コピーできませんでした' })).toBeVisible()
  await expect(feedback).toHaveText('')
  await expect(copy).toBeEnabled()
})
