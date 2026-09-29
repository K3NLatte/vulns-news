import { test as base, expect, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import type { FeedItem, FeedResult } from '../src/types/feed'

// 正常系はポート8080のGo APIを使用し、異常・途中経過だけを上書きする。
const test = base.extend<{ checkErrors: void }>({
  checkErrors: [async ({ page }, use) => {
    const errors: string[] = []
    page.on('pageerror', error => errors.push(error.message))
    await use()
    expect(errors).toEqual([])
  }, { auto: true }],
})
const repository = 'https://github.com/example/mock-service'
const articles = (page: Page) => page.getByRole('list', { name: '脆弱性記事', exact: true })
const status = (page: Page) => page.getByLabel('リポジトリの解析状況')
function recordRequests(page: Page) {
  const requests: string[] = []
  page.on('request', request => {
    const path = new URL(request.url()).pathname
    if (path.startsWith('/api/')) requests.push(`${request.method()} ${path}`)
  })
  return requests
}
async function registerRepository(page: Page, url = repository) {
  await page.getByLabel('公開リポジトリ', { exact: true }).fill(url)
  const accepted = page.waitForResponse(response => new URL(response.url()).pathname === '/api/repositories'
    && response.request().method() === 'POST')
  await page.getByRole('button', { name: '読み込む', exact: true }).click()
  const response = await accepted
  expect(response.status()).toBe(202)
  expect(response.request().postDataJSON()).toEqual({ url })
  expect(await response.json()).toEqual({ repository_id: 'repo-001', job_id: 'job-001' })
}

test('Goの一覧を一度取得し、検索・絞り込み・並べ替えと記事からの復帰を行う', async ({ page }) => {
  const requests = recordRequests(page)
  await page.goto('/#/feed')
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await expect(page.locator('#detail-title')).toBeVisible()
  await page.getByLabel('記事を検索').fill('ｓａｍｐｌｅｖｉｅｗ')
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  await page.getByRole('button', { name: '検索をクリア' }).click()
  await page.getByLabel('CVSS重要度').selectOption('high')
  await expect(articles(page).getByRole('listitem')).toHaveCount(5)
  await page.getByLabel('CVSS重要度').selectOption('all')
  await page.getByLabel('並び順').selectOption('severity')
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  expect(requests.filter(path => path === 'GET /api/cves')).toHaveLength(1)

  const row = page.locator('#article-demo-008')
  await row.scrollIntoViewIfNeeded()
  const scrollBefore = await page.evaluate(() => scrollY)
  expect(scrollBefore).toBeGreaterThan(0)
  await row.click()
  await expect(page.locator('#detail-title')).toBeFocused()
  expect(Math.abs(await page.evaluate(() => scrollY) - scrollBefore)).toBeLessThan(3)
  expect(requests).toContain('GET /api/cves/demo-008')
  const expand = page.getByRole('button', { name: 'ページで開く', exact: true })
  await expand.scrollIntoViewIfNeeded()
  const scrollBeforeExpand = await page.evaluate(() => scrollY)
  await expand.click()
  await expect(page).toHaveURL(/#\/article\/demo-008$/)
  await expect(page).toHaveTitle(/DEMO-2026-008/)
  await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
  await expect(row).toBeFocused()
  await expect.poll(async () => Math.abs(await page.evaluate(() => scrollY) - scrollBeforeExpand)).toBeLessThan(3)
})

test('未選択の行のページリンクから戻ると、その記事の選択・詳細・焦点を保持する', async ({ page }) => {
  const requests = recordRequests(page)
  await page.goto('/#/feed')
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await expect(page.locator('#article-demo-001')).toHaveAttribute('aria-current', 'true')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
  await page.getByRole('link', { name: 'DEMO-2026-003をページで開く', exact: true }).click()
  await expect(page).toHaveURL(/#\/article\/demo-003$/)
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
  await expect(page).toHaveURL(/#\/feed$/)
  await expect(page.locator('#article-demo-003')).toHaveAttribute('aria-current', 'true')
  await expect(page.locator('#article-demo-003')).toBeFocused()
  await expect(page.locator('#article-demo-001')).not.toHaveAttribute('aria-current', 'true')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  expect(requests).toContain('GET /api/cves/demo-003')
})

test('表示済み記事をページで開くと、詳細を再取得せず見出しへ焦点を移す', async ({ page }) => {
  const requests = recordRequests(page)
  await page.goto('/#/feed')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
  await expect(page.locator('h2#detail-title')).toBeVisible()
  expect(requests.filter(path => path === 'GET /api/cves/demo-001')).toHaveLength(1)
  await page.getByRole('button', { name: 'ページで開く', exact: true }).click()
  await expect(page).toHaveURL(/#\/article\/demo-001$/)
  await expect(page.locator('h1#detail-title')).toBeFocused()
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
  expect(requests.filter(path => path === 'GET /api/cves/demo-001')).toHaveLength(1)
})

test('モバイルで一覧から記事を開いて戻り、アクセシビリティを検証する', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto('/#/feed')
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  const row = page.locator('#article-demo-005')
  await row.click()
  await expect(page).toHaveURL(/#\/article\/demo-005$/)
  await expect(page.locator('#detail-title')).toBeFocused()
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-005')
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  const accessibility = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze()
  expect(accessibility.violations).toEqual([])
  await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
  await expect(page).toHaveURL(/#\/feed$/)
  await expect(row).toBeFocused()
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
})

test('公開リポジトリは送信時だけ登録され、絞り込みと再読み込みで再登録されない', async ({ page }) => {
  const requests = recordRequests(page)
  await page.goto('/#/repositories')
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toBeVisible()
  await expect(page.locator('a[href="#/analyze"], a[href="#/saved"], a[href="#/settings"], .save-button')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'ログイン', exact: true })).toHaveCount(0)
  expect(requests).toEqual([])
  await registerRepository(page)
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  await expect(status(page)).toContainText('解析完了')
  await expect(status(page)).toContainText('処理済み 6 / 6件')
  expect(requests).toContain('GET /api/jobs/job-001')
  expect(requests).toContain('GET /api/repositories/repo-001/feed')
  await page.getByLabel('並び順').selectOption('relevance')
  await page.getByLabel('記事を検索').fill('SampleView')
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  await page.getByRole('button', { name: '検索をクリア' }).click()
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  expect(requests.filter(path => path === 'GET /api/repositories/repo-001/feed')).toHaveLength(1)
  await page.locator('#article-demo-005').click()
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  expect(requests).toContain('GET /api/repositories/repo-001/feed/demo-005')
  await page.reload()
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  expect(requests.filter(path => path === 'POST /api/repositories')).toHaveLength(1)
})

test('未評価の解析済み応答は、一覧と詳細の両方で未確定として表示する', async ({ page }) => {
  await page.route('**/api/repositories/repo-001/feed', async route => {
    const response = await route.fetch()
    const feed: FeedResult = await response.json()
    const items = feed.items.map((item, index) => index === 0
      ? { ...item, assessment: 'unverified', repositoryAnalysis: 'analyzed' } : item)
    await route.fulfill({ response, json: { ...feed, items } })
  })
  await page.route('**/api/repositories/repo-001/feed/demo-001', async route => {
    const response = await route.fetch()
    await route.fulfill({ response, json: {
      ...await response.json(), assessment: 'unverified', repositoryAnalysis: 'analyzed',
    } })
  })
  await page.goto('/#/repositories')
  await registerRepository(page)
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  await page.getByRole('group', { name: '解析結果の絞り込み' }).getByRole('button', { name: /^未確定/ }).click()
  await expect(articles(page).getByRole('listitem')).toHaveCount(2)
  const row = articles(page).getByRole('listitem').filter({ has: page.locator('#article-demo-001') })
  await expect(row).toContainText('未評価')
  await expect(row).toContainText('未確定')
  await expect(row).toContainText('対応優先度 要確認')
  await expect(row).toContainText('関連度 未確定')
  await expect(row).not.toContainText('分析済み')
  await expect(row).not.toContainText('関連度 74')
  await expect(row).not.toContainText('対応優先度 高')
  await page.locator('#article-demo-001').click()
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  await expect(page.locator('.analysis-section, .poc-section')).toHaveCount(0)
})

test('別リポジトリを登録していても、記事リンクの再読み込み後はそのリポジトリ一覧へ戻る', async ({ page }) => {
  const requests = recordRequests(page)
  const registrations: string[] = []
  const secondRepository = 'https://github.com/example/second-service'
  page.on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/repositories') {
      registrations.push(request.postDataJSON().url)
    }
  })
  await page.goto('/#/repositories')
  await registerRepository(page)
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  await registerRepository(page, secondRepository)
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveValue(secondRepository)
  await expect(page.locator('.feed-detail')).toContainText('example/second-service')
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)

  await page.goto(`/#/article/demo-003?repository=${encodeURIComponent(repository)}`)
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await page.reload()
  await expect(page.locator('.feed-detail')).toContainText('example/mock-service')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
  await expect(page).toHaveURL(/#\/repositories$/)
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveValue(repository)
  await expect(page.locator('#article-demo-003')).toHaveAttribute('aria-current', 'true')
  await expect(page.locator('#article-demo-003')).toBeFocused()
  await expect(page.locator('.feed-detail')).toContainText('example/mock-service')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await expect(page.getByRole('link', { name: 'DEMO-2026-003をページで開く', exact: true }))
    .toHaveAttribute('href', `#/article/demo-003?repository=${encodeURIComponent(repository)}`)
  expect(registrations).toEqual([repository, secondRepository])
  expect(requests.filter(path => path === 'POST /api/repositories')).toHaveLength(2)
  expect(requests).toContain('GET /api/repositories/repo-001/feed/demo-003')
  expect(requests).not.toContain('GET /api/cves/demo-003')
})

test('ブラウザ履歴で以前のリポジトリ記事へ戻ると、その対象と選択を一覧へ引き継ぐ', async ({ page }) => {
  const requests = recordRequests(page)
  const secondRepository = 'https://github.com/example/second-service'
  await page.goto('/#/repositories')
  await registerRepository(page)
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  await page.locator('#article-demo-003').click()
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await page.getByRole('button', { name: 'ページで開く', exact: true }).click()
  const firstArticleUrl = new URL(`/#/article/demo-003?repository=${encodeURIComponent(repository)}`, page.url()).href
  await expect(page).toHaveURL(firstArticleUrl)
  await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
  await expect(page).toHaveURL(/#\/repositories$/)
  await registerRepository(page, secondRepository)
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveValue(secondRepository)
  await expect(page.locator('.feed-detail')).toContainText('example/second-service')

  await page.goBack()
  await expect(page).toHaveURL(firstArticleUrl)
  await expect(page.locator('.feed-detail')).toContainText('example/mock-service')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await page.getByRole('button', { name: '一覧に戻る', exact: true }).click()
  await expect(page).toHaveURL(/#\/repositories$/)
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveValue(repository)
  await expect(page.locator('#article-demo-003')).toHaveAttribute('aria-current', 'true')
  await expect(page.locator('#article-demo-003')).toBeFocused()
  await expect(page.locator('.feed-detail')).toContainText('example/mock-service')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await expect(page.getByRole('link', { name: 'DEMO-2026-003をページで開く', exact: true }))
    .toHaveAttribute('href', `#/article/demo-003?repository=${encodeURIComponent(repository)}`)
  expect(requests.filter(path => path === 'POST /api/repositories')).toHaveLength(2)
  expect(requests).not.toContain('GET /api/cves/demo-003')
})

test('記事の直接リンクは一覧APIが停止していても詳細を読み、実在しないIDは404になる', async ({ page }) => {
  const requests = recordRequests(page)
  await page.route('**/api/cves?*', route => route.fulfill({ status: 503, body: 'list unavailable' }))
  await page.goto('/#/article/demo-012')
  await expect(page.locator('#detail-title')).toHaveText('エラーページに内部パスと構成情報が表示される')
  await expect(page).toHaveTitle(/DEMO-2026-012/)
  expect(requests).toContain('GET /api/cves/demo-012')
  expect(requests.filter(path => path === 'GET /api/cves')).toHaveLength(0)

  const missing = page.waitForResponse(response => new URL(response.url()).pathname === '/api/cves/nonexistent-article')
  await page.goto('/#/article/nonexistent-article')
  expect((await missing).status()).toBe(404)
  await expect(page.getByRole('alert')).toContainText('見つかりません')
  await expect(page.locator('#detail-title')).toHaveCount(0)
  await expect(articles(page)).toHaveCount(0)
  expect(requests.filter(path => path === 'GET /api/cves')).toHaveLength(0)
})

test('未登録のリポジトリ記事はURLを提示し、明示的な送信後に詳細APIを使う', async ({ page }) => {
  const requests = recordRequests(page)
  await page.route('**/api/repositories/repo-001/feed', route => route.fulfill({ status: 503, body: 'list unavailable' }))
  await page.goto(`/#/article/demo-005?repository=${encodeURIComponent(repository)}`)
  await expect(page.getByLabel('公開リポジトリ', { exact: true })).toHaveValue(repository)
  expect(requests).toEqual([])
  await registerRepository(page)
  await expect(page.locator('#detail-title')).toBeVisible()
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  expect(requests).toContain('GET /api/repositories/repo-001/feed/demo-005')
  expect(requests.filter(path => path === 'GET /api/repositories/repo-001/feed')).toHaveLength(0)
  await page.reload()
  await expect(page.locator('#detail-title')).toBeVisible()
  expect(requests.filter(path => path === 'POST /api/repositories')).toHaveLength(1)
})

test('HTTPエラー本文を表示せず、一覧と詳細をそれぞれ再試行する', async ({ page }) => {
  let fail = true
  const privateMessage = 'SECRET_INTERNAL_PATH <img src=x onerror=alert(1)>'
  await page.route('**/api/cves?*', route => fail
    ? route.fulfill({ status: 500, contentType: 'text/plain', body: privateMessage }) : route.continue())
  await page.goto('/#/feed')
  await expect(page.getByRole('alert')).toContainText('HTTP 500')
  await expect(articles(page)).toHaveCount(0)
  await expect(page.locator('body')).not.toContainText('SECRET_INTERNAL_PATH')
  fail = false
  await page.getByRole('button', { name: '再試行', exact: true }).click()
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await expect(page.locator('#detail-title')).toBeVisible()

  await page.route('**/api/cves/demo-002', route => route.fulfill({ status: 404, body: privateMessage }))
  await page.locator('#article-demo-002').click()
  await expect(page.getByRole('alert')).toContainText('見つかりません')
  await expect(page.locator('#detail-title')).toHaveCount(0)
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await expect(page.locator('body')).not.toContainText('SECRET_INTERNAL_PATH')
  await page.unroute('**/api/cves/demo-002')
  await page.getByRole('button', { name: '再試行', exact: true }).click()
  await expect(page.locator('#detail-title')).toHaveText('共有キャッシュのキー衝突で別ユーザーの応答が返る')
})

test('詳細取得に失敗してから検索しても、成功した別記事へ入力中の焦点を移さない', async ({ page }) => {
  await page.route('**/api/cves/demo-002', route => route.fulfill({ status: 500, body: 'detail unavailable' }))
  await page.goto('/#/feed')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
  await page.locator('#article-demo-002').click()
  await expect(page.getByRole('alert')).toContainText('HTTP 500')
  const search = page.getByLabel('記事を検索')
  await search.fill('SampleView')
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
  await expect(search).toBeFocused()
  await page.keyboard.insertText(' Engine')
  await expect(search).toHaveValue('SampleView Engine')
  await expect(search).toBeFocused()
})

test('詳細の応答待ちに検索へ入力すると、新旧どちらの応答も焦点を奪わない', async ({ page }) => {
  let release!: () => void
  const held = new Promise<void>(resolve => { release = resolve })
  let received!: () => void
  const intercepted = new Promise<void>(resolve => { received = resolve })
  let settled = false
  await page.route('**/api/cves/demo-002', async route => {
    const response = await route.fetch()
    received()
    await held
    try { await route.fulfill({ response }) } finally { settled = true }
  })
  const search = page.getByLabel('記事を検索')
  try {
    await page.goto('/#/feed')
    await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
    await page.locator('#article-demo-002').click()
    await intercepted
    await expect(page.locator('#detail-title')).toHaveCount(0)
    await search.fill('SampleView')
    await expect(articles(page).getByRole('listitem')).toHaveCount(1)
    await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
    await expect(search).toBeFocused()
  } finally { release() }
  await expect.poll(() => settled).toBe(true)
  await expect(search).toBeFocused()
  await page.keyboard.insertText(' Engine')
  await expect(search).toHaveValue('SampleView Engine')
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
})

test('検索で自動選択された表示済み記事はEnterで焦点を移し、次の検索では入力を維持する', async ({ page }) => {
  const requests = recordRequests(page)
  await page.goto('/#/feed')
  await expect(articles(page).getByRole('listitem')).toHaveCount(12)
  await page.locator('#article-demo-003').click()
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await expect(page.locator('#detail-title')).toBeFocused()
  const search = page.getByLabel('記事を検索')
  await search.fill('SampleView')
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-001')
  await expect(search).toBeFocused()
  const detailRequests = requests.filter(path => path === 'GET /api/cves/demo-001').length
  const row = page.locator('#article-demo-001')
  await row.focus()
  await page.keyboard.press('Enter')
  await expect(page.locator('h2#detail-title')).toBeFocused()
  expect(requests.filter(path => path === 'GET /api/cves/demo-001')).toHaveLength(detailRequests)
  await search.fill('DEMO-2026-003')
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await expect(search).toBeFocused()
  await page.keyboard.insertText(' ')
  await expect(search).toHaveValue('DEMO-2026-003 ')
  await expect(search).toBeFocused()
})

test('APIのPoCを表示し、共有失敗時はリポジトリ情報を含まない選択可能なURLを出す', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'share', {
      value: async () => { throw new Error('共有を利用できません') }, configurable: true,
    })
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: async () => { throw new DOMException('コピーが拒否されました', 'NotAllowedError') } },
      configurable: true,
    })
  })
  await page.goto(`/?scenario=loading&account=private#/article/demo-001?repository=${encodeURIComponent(repository)}`)
  const detailResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/repositories/repo-001/feed/demo-001')
  await registerRepository(page)
  const item: FeedItem = await (await detailResponse).json()
  expect(item.proofOfConcept).toBeDefined()
  await expect(page.locator('#detail-title')).toHaveText(item.title)
  await page.locator('.poc-section summary').click()
  await expect(page.locator('.poc-section pre code')).toHaveText(item.proofOfConcept!.code)
  await expect(page.locator('.poc-conditions')).toContainText(item.proofOfConcept!.conditions[0]!)
  await expect(page.locator('.save-button, .triage-section, .comment-thread')).toHaveCount(0)

  const share = page.getByRole('button', { name: '共有', exact: true })
  await share.click()
  const shareUrl = page.getByLabel('共有URL', { exact: true })
  await expect(shareUrl).toHaveValue(new URL('/#/article/demo-001', page.url()).href)
  await expect(shareUrl).toBeFocused()
  await expect.poll(() => shareUrl.evaluate((input: HTMLInputElement) => ({ start: input.selectionStart, end: input.selectionEnd, length: input.value.length })))
    .toMatchObject({ start: 0, end: (await shareUrl.inputValue()).length })
  await expect(page.getByRole('region', { name: 'リンクの共有', exact: true })).toContainText('URLを選択してコピーしてください')
  await page.keyboard.press('Escape')
  await expect(shareUrl).toHaveCount(0)
  await expect(share).toBeFocused()
})

test('選択中の途中結果が分析済みに変わると、同じ記事の詳細を再取得して本文を更新する', async ({ page }) => {
  const requests = recordRequests(page)
  let completed = false
  const completedSummary = '解析が完了し、公開プレビューの利用箇所まで確認できました。'
  function updatedItem(item: FeedItem): FeedItem {
    return {
      ...item,
      repositoryAnalysis: completed ? 'analyzed' : 'pending',
      updatedAt: completed ? '2026-09-30T03:00:00.000Z' : item.updatedAt,
      analysis: { ...item.analysis, summary: completed ? completedSummary : item.analysis.summary },
    }
  }
  await page.route('**/api/jobs/job-001', async route => {
    const response = await route.fetch()
    const job = await response.json()
    await route.fulfill({ response, json: {
      ...job, stage: completed ? 'completed' : 'analyzing', processed: completed ? 6 : 1,
      confirmedCount: completed ? 5 : 0, pendingCount: 1, hasAvailableResults: true,
    } })
  })
  await page.route('**/api/repositories/repo-001/feed', async route => {
    const response = await route.fetch()
    const feed: FeedResult = await response.json()
    const items = (completed ? feed.items : feed.items.slice(0, 1))
      .map(item => item.id === 'demo-001' ? updatedItem(item) : item)
    await route.fulfill({ response, json: { ...feed, items, matchedTotal: items.length } })
  })
  await page.route('**/api/repositories/repo-001/feed/demo-001', async route => {
    const response = await route.fetch()
    await route.fulfill({ response, json: updatedItem(await response.json()) })
  })
  await page.goto('/#/repositories')
  await registerRepository(page)
  await expect(articles(page).getByRole('listitem')).toHaveCount(1)
  await expect(page.locator('#article-demo-001')).toHaveAttribute('aria-current', 'true')
  await expect(page.locator('.pending-analysis-note')).toBeVisible()
  await expect(page.locator('.analysis-section, .poc-section')).toHaveCount(0)
  await expect.poll(() => requests.filter(path => path === 'GET /api/repositories/repo-001/feed').length).toBeGreaterThanOrEqual(2)
  expect(requests.filter(path => path === 'GET /api/repositories/repo-001/feed/demo-001')).toHaveLength(1)

  completed = true
  await expect(status(page)).toContainText('解析完了')
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  await expect(page.locator('#article-demo-001')).toHaveAttribute('aria-current', 'true')
  await expect(page.locator('.pending-analysis-note')).toHaveCount(0)
  await expect(page.locator('.analysis-section')).toContainText(completedSummary)
  await expect(page.locator('.detail-footer time')).toHaveAttribute('datetime', '2026-09-30T03:00:00.000Z')
  expect(requests.filter(path => path === 'GET /api/repositories/repo-001/feed/demo-001')).toHaveLength(2)
  expect(requests.filter(path => path === 'POST /api/repositories')).toHaveLength(1)
})

test('途中結果の詳細が応答待ちでも完了結果を再取得し、遅れた途中結果で上書きしない', async ({ page }) => {
  const requests = recordRequests(page)
  let completed = false
  let detailCalls = 0
  let released = false
  let release!: () => void
  const held = new Promise<void>(resolve => { release = resolve })
  let received!: () => void
  const intercepted = new Promise<void>(resolve => { received = resolve })
  const completedSummary = '完了後の再取得で、対象コードへの影響と修正版を確認しました。'
  function updatedItem(item: FeedItem, isCompleted: boolean): FeedItem {
    return {
      ...item, repositoryAnalysis: isCompleted ? 'analyzed' : 'pending',
      updatedAt: isCompleted ? '2026-09-30T04:00:00.000Z' : item.updatedAt,
      analysis: { ...item.analysis, summary: isCompleted ? completedSummary : item.analysis.summary },
    }
  }
  await page.route('**/api/jobs/job-001', async route => {
    const response = await route.fetch()
    const job = await response.json()
    await route.fulfill({ response, json: {
      ...job, stage: completed ? 'completed' : 'analyzing', processed: completed ? 6 : 1,
      confirmedCount: completed ? 5 : 0, pendingCount: 1, hasAvailableResults: true,
    } })
  })
  await page.route('**/api/repositories/repo-001/feed', async route => {
    const response = await route.fetch()
    const feed: FeedResult = await response.json()
    const items = (completed ? feed.items : feed.items.slice(0, 1))
      .map(item => item.id === 'demo-001' ? updatedItem(item, completed) : item)
    await route.fulfill({ response, json: { ...feed, items, matchedTotal: items.length } })
  })
  await page.route('**/api/repositories/repo-001/feed/demo-001', async route => {
    const call = ++detailCalls
    const response = await route.fetch()
    const item = updatedItem(await response.json(), completed)
    if (call === 1) {
      received()
      await held
      try { await route.fulfill({ response, json: item }) } finally { released = true }
    } else await route.fulfill({ response, json: item })
  })
  try {
    await page.goto('/#/repositories')
    await registerRepository(page)
    await intercepted
    await expect(articles(page).getByRole('listitem')).toHaveCount(1)
    await expect(page.locator('#detail-title')).toHaveCount(0)
    completed = true
    await expect(status(page)).toContainText('解析完了')
    await expect(articles(page).getByRole('listitem')).toHaveCount(6)
    await expect(page.locator('.analysis-section')).toContainText(completedSummary)
    expect(detailCalls).toBe(2)
  } finally { release() }
  await expect.poll(() => released).toBe(true)
  await expect(page.locator('.analysis-section')).toContainText(completedSummary)
  await expect(page.locator('.pending-analysis-note')).toHaveCount(0)
  await expect(page.locator('.detail-footer time')).toHaveAttribute('datetime', '2026-09-30T04:00:00.000Z')
  await expect(page.locator('#article-demo-001')).toHaveAttribute('aria-current', 'true')
  expect(requests.filter(path => path === 'POST /api/repositories')).toHaveLength(1)
})

test('途中結果を表示し、ジョブ失敗後も保持して追加POSTなしで再試行する', async ({ page }) => {
  const requests = recordRequests(page)
  let phase: 'analyzing' | 'failed' | 'completed' = 'analyzing'
  await page.route('**/api/jobs/job-001', async route => {
    const response = await route.fetch()
    const job = await response.json()
    await route.fulfill({ response, json: {
      ...job, stage: phase, processed: phase === 'completed' ? 6 : 2,
      confirmedCount: phase === 'completed' ? 5 : 2, pendingCount: phase === 'completed' ? 1 : 0,
      hasAvailableResults: true,
      ...(phase === 'failed' ? { errorMessage: 'SECRET_JOB_TOKEN <script>alert(1)</script>' } : {}),
    } })
  })
  await page.route('**/api/repositories/repo-001/feed', async route => {
    const response = await route.fetch()
    const feed = await response.json()
    const items = phase === 'completed' ? feed.items : feed.items.slice(0, 2)
    await route.fulfill({ response, json: { ...feed, items, matchedTotal: items.length } })
  })
  await page.goto('/#/repositories')
  await registerRepository(page)
  await expect(articles(page).getByRole('listitem')).toHaveCount(2)
  await expect(status(page)).toContainText('処理済み 2 / 6件')
  await expect(status(page)).toContainText('確認できた記事から表示')
  phase = 'failed'
  await expect(status(page)).toContainText('解析を完了できませんでした')
  await expect(articles(page).getByRole('listitem')).toHaveCount(2)
  await expect(page.locator('body')).not.toContainText('SECRET_JOB_TOKEN')
  expect(requests.filter(path => path === 'GET /api/jobs/job-001').length).toBeGreaterThanOrEqual(2)
  phase = 'completed'
  await page.getByRole('button', { name: '再試行', exact: true }).click()
  await expect(articles(page).getByRole('listitem')).toHaveCount(6)
  await expect(status(page)).toContainText('解析完了')
  expect(requests.filter(path => path === 'POST /api/repositories')).toHaveLength(1)
})

test('選択変更で古い詳細リクエストを中断し、遅れた応答を表示しない', async ({ page }) => {
  let release!: () => void
  const held = new Promise<void>(resolve => { release = resolve })
  let received!: () => void
  const intercepted = new Promise<void>(resolve => { received = resolve })
  let settled = false
  const failedRequests: string[] = []
  page.on('requestfailed', request => failedRequests.push(new URL(request.url()).pathname))
  await page.route('**/api/cves/demo-002', async route => {
    const response = await route.fetch()
    received()
    await held
    try { await route.fulfill({ response }) } finally { settled = true }
  })
  await page.goto('/#/feed')
  await expect(page.locator('#detail-title')).toBeVisible()
  await page.locator('#article-demo-002').click()
  await intercepted
  await page.locator('#article-demo-003').click()
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await expect.poll(() => failedRequests).toContain('/api/cves/demo-002')
  release()
  await expect.poll(() => settled).toBe(true)
  await expect(page.locator('.feed-detail')).toContainText('DEMO-2026-003')
  await expect(page.locator('.feed-detail')).not.toContainText('DEMO-2026-002')
})
