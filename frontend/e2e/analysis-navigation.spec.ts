import { expect, test as base } from '@playwright/test'

const test = base.extend<{ checkErrors: void }>({
  checkErrors: [async ({ page }, use) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    await use()
    expect(errors).toEqual([])
  }, { auto: true }],
})

test('analysis report return restores the lower list position and the originating link', async ({ page }) => {
  // Keep the fixture tracking windows stable without freezing browser navigation.
  await page.clock.setFixedTime(new Date('2026-09-25T00:00:00.000Z'))
  await page.goto('/#/analyze')
  const link = page.locator('.report-entry h3 a').last()
  await link.scrollIntoViewIfNeeded()
  const id = await link.getAttribute('id')
  const previousScroll = await page.evaluate(() => scrollY)
  expect(previousScroll).toBeGreaterThan(500)

  for (const returnUsing of ['button', 'browser'] as const) {
    await link.focus()
    await page.keyboard.press('Enter')
    await expect(page.locator('h1#detail-title')).toBeVisible()
    if (returnUsing === 'button') {
      await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
    } else {
      await page.goBack()
    }
    await expect(page).toHaveURL(/#\/analyze$/)
    await expect(page.getByRole('button', { name: /^追跡中/ })).toHaveAttribute('aria-pressed', 'true')
    await expect(page.locator(`[id="${id}"]`)).toBeFocused()
    await expect.poll(() => page.evaluate(() => scrollY)).toBeCloseTo(previousScroll, 0)
    // Returning should not remove the report link from the normal tab order.
    await expect(link).not.toHaveAttribute('tabindex', '-1')
  }
})

test('expired report return retains its filter and focus through mouse and browser navigation', async ({ page }) => {
  await page.clock.setFixedTime(new Date('2026-09-25T00:00:00.000Z'))
  await page.goto('/#/analyze')
  const expired = page.getByRole('button', { name: /^期限終了/ })
  await expired.click()
  const link = page.locator('.report-entry h3 a').last()
  const id = await link.getAttribute('id')
  const reportsBefore = await page.locator('.report-entry h3 a').allTextContents()
  expect(reportsBefore.length).toBeGreaterThan(0)

  for (const returnUsing of ['button', 'browser'] as const) {
    await link.click()
    await expect(page.locator('h1#detail-title')).toBeVisible()
    if (returnUsing === 'button') {
      await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
    } else {
      await page.goBack()
    }
    await expect(expired).toHaveAttribute('aria-pressed', 'true')
    await expect(page.locator(`[id="${id}"]`)).toBeFocused()
    expect(await page.locator('.report-entry h3 a').allTextContents()).toEqual(reportsBefore)
  }
})
