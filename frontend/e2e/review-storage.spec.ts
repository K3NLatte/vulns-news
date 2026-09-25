import { expect, test, type Page } from '@playwright/test'

const activeKey = 'vulns-news:workspace:active:v1'
const guestKey = 'vulns-news:workspace:guest:v1'
const profileKey = 'vulns-news:workspace:profile:v1:alice'

async function login(page: Page) {
  await page.getByRole('navigation', { name: 'メインメニュー' }).getByRole('button', { name: 'ログイン', exact: true }).click()
  await page.getByLabel('表示名', { exact: true }).fill('Alice')
  await page.getByRole('dialog').getByRole('button', { name: 'ログイン', exact: true }).click()
  await expect(page.getByRole('dialog')).not.toBeVisible()
}

test('a failed logout displays its reason inside the still-open account dialog', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.goto('/#/feed')
  await login(page)
  await page.evaluate(key => {
    const remove = Storage.prototype.removeItem
    Storage.prototype.removeItem = function (this: Storage, name: string) {
      if (this === sessionStorage && name === key) throw new DOMException('Blocked for test', 'SecurityError')
      remove.call(this, name)
    }
  }, activeKey)
  await page.getByRole('button', { name: 'Alice のアカウントを開く', exact: true }).click()
  const dialog = page.getByRole('dialog')
  const logout = dialog.getByRole('button', { name: 'ログアウト', exact: true })
  await logout.click()
  await expect(dialog).toBeVisible()
  await expect(dialog.getByRole('alert')).toContainText('ログイン状態を保存できません')
  await expect(logout).toBeFocused()
  await page.reload()
  await expect(page.getByRole('button', { name: 'Alice のアカウントを開く', exact: true })).toBeVisible()
  expect(errors).toEqual([])
})

test('reloading another tab save moves focus out of the removed recovery banner', async ({ page, context }) => {
  await page.goto('/#/feed')
  await login(page)
  const second = await context.newPage()
  await second.goto('/#/feed')
  await second.evaluate(key => {
    const raw = localStorage.getItem(key)
    if (!raw) throw new Error('Expected existing profile')
    const profile = JSON.parse(raw)
    profile.data.savedIds.push('demo-002')
    localStorage.setItem(key, JSON.stringify(profile))
  }, profileKey)
  const reload = page.getByRole('button', { name: '最新の保存内容を読み込む', exact: true })
  await expect(reload).toBeVisible()
  await reload.click()
  await expect(page.locator('.storage-error')).toHaveCount(0)
  await expect(page.locator('#main-content')).toBeFocused()
  await expect(page.getByRole('button', { name: 'Alice のアカウントを開く', exact: true })).toBeVisible()
  await second.close()
})

test('recovering corrupt data keeps its original backup and restores keyboard focus', async ({ page }) => {
  await page.addInitScript(key => sessionStorage.setItem(key, '{broken'), guestKey)
  await page.goto('/#/feed')
  const recover = page.getByRole('button', { name: '保存内容を復旧', exact: true })
  await expect(recover).toBeVisible()
  page.once('dialog', dialog => void dialog.accept())
  await recover.click()
  await expect(page.locator('.storage-error')).toHaveCount(0)
  await expect(page.locator('#main-content')).toBeFocused()
  const originals = await page.evaluate(key => Object.keys(sessionStorage)
    .filter(name => name.startsWith(key + ':recovery:')).map(name => sessionStorage.getItem(name)), guestKey)
  expect(originals).toEqual(['{broken'])
})
