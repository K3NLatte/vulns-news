import { expect, test } from '@playwright/test'

test('production ignores URL controls that simulate empty, loading, failed, or completed results', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/#/settings')
  await page.getByLabel('GitHubリポジトリのURL').fill('https://github.com/example/backend')
  await page.getByRole('button', { name: '追加', exact: true }).click()
  for (const scenario of ['empty', 'loading', 'error']) {
    await page.goto(`/?analysis=failed&scenario=${scenario}&view=mvp#/repositories`)
    await expect(page.getByRole('list', { name: '脆弱性記事', exact: true }).getByRole('listitem')).toHaveCount(5)
    await expect(page.getByRole('link', { name: '追加・管理' })).toBeVisible()
    await expect(page.locator('.repository-history-status')).toContainText('過去情報は未検索')
  }
  await page.goto('/?analysis=completed&scenario=empty#/repositories')
  await expect(page.getByRole('list', { name: '脆弱性記事', exact: true }).getByRole('listitem')).toHaveCount(5)
  expect(errors).toEqual([])
})
