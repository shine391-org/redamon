import { test, expect, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { mintToken, signIn } from './auth'

/**
 * The Priority Board's disposition (plan 10.2b): a chip per row with its
 * blocker as the tooltip, a filter beside Decided by, a line in the detail
 * panel, and an icon-only chip on a narrow screen. Then the report's new top
 * summary (10.2).
 *
 * The board tests serve the findings answer from the test, so every
 * disposition is on screen whatever the project holds; one test also reads the
 * project's own board and requires a chip on every live row. The report is
 * rendered on the server, so it is opened from REDAMON_REPORT_HTML when set,
 * else the project's newest stored report; REDAMON_EXPECT_CANDIDATES, when set,
 * is the candidate total it must print.
 *
 * Plan 10.5: a stubbed row shows the blocker a run stored over its tier rule,
 * and with REDAMON_EXPECT_STORED=1 (after a v3.10 Priority Board run) every
 * live candidate names the gate, or the AI review, that holds it.
 *
 * Requires the stack (the built webapp image). Run:
 *   REDAMON_PROJECT=<id> REDAMON_USER=<owner id> npx playwright test dispositionBoard
 */

const PROJECT = process.env.REDAMON_PROJECT || ''
const USER = process.env.REDAMON_USER || ''
const REPORT_HTML = process.env.REDAMON_REPORT_HTML
const EXPECT_CANDIDATES = process.env.REDAMON_EXPECT_CANDIDATES

const base = {
  label: 'Vulnerability', source: 'nuclei', triage_state: 'open', triage_status: 'unreviewed',
  triage_confidence: null, triage_reason: null, triage_source: '', triage_signals: [],
  triage_run_id: 'run-e2e', triaged_at: '2026-10-01T00:00:00Z', triage_priority_score: 40,
  triage_tier: 'T3', triage_factors: null, triage_ai_verdict: '', triage_decided_by: 'rules',
}

const ROWS = [
  { ...base, id: 'e2e-reportable', name: 'Proven SQL injection', severity: 'high', section: 0,
    triage_tier: 'T1', triage_tier_rule: 'proven', triage_priority_score: 95 },
  { ...base, id: 'e2e-candidate', name: 'Outdated server banner', severity: 'medium', section: 0,
    triage_tier_rule: 'credible, with impact worth planning for' },
  { ...base, id: 'e2e-info', label: 'Secret', name: 'Browser key', severity: 'info', section: 0,
    triage_tier: 'T4', triage_tier_rule: 'no rule placed this higher', public_client_key: true,
    secret_type: 'GCP API Key', triage_priority_score: 5 },
  { ...base, id: 'e2e-untriaged', name: 'Fresh finding', severity: 'high', section: 1,
    triage_run_id: '', triaged_at: null, triage_priority_score: null, triage_tier: '', triage_tier_rule: '' },
  { ...base, id: 'e2e-ai-fp', name: 'Debug page', severity: 'low', section: 2,
    triage_state: 'false_positive', triage_decided_by: 'review', triage_priority_score: 0,
    triage_tier: 'T4', triage_tier_rule: 'the AI review found it a false positive' },
  { ...base, id: 'e2e-gone', name: 'Old CVE', severity: 'critical', section: 3,
    triage_state: 'gone', triage_tier_rule: 'credible, with impact worth planning for' },
]

test.skip(!PROJECT || !USER, 'set REDAMON_PROJECT and REDAMON_USER')

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

async function openBoard(page: Page, stub = true, rows: Record<string, unknown>[] = ROWS) {
  if (stub) {
    await page.route('**/api/triage/findings?*', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ findings: rows, total: rows.length, latestRunId: 'run-e2e' }),
    }))
    await page.route('**/api/triage/finding?*', route => {
      const id = new URL(route.request().url()).searchParams.get('findingId')
      const row = rows.find(r => r.id === id)
      return route.fulfill({
        status: 200, contentType: 'application/json',
        body: JSON.stringify({ row, group: [], detector: { key: '', real: 0, fp: 0 } }),
      })
    })
    await page.route('**/api/triage/evidence?*', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ evidence: '', matches_last_run: true, reviewable: false,
        not_reviewable_because: null, review_survives_rescan: true }),
    }))
  }
  await page.goto(`/graph?project=${PROJECT}&table=triage`)
  await expect(page.getByRole('combobox', { name: 'Disposition' })).toBeVisible()
}

const chipOf = (page: Page, name: string) =>
  page.locator('tr', { hasText: name }).locator('[data-disposition]')

test('Board: every row carries its disposition, with the blocker as the tooltip', async ({ page }) => {
  await openBoard(page)
  const want: Array<[string, string, string]> = [
    ['Proven SQL injection', 'reportable', 'Reportable'],
    ['Outdated server banner', 'candidate', 'Candidate, blocked by credible, with impact worth planning for'],
    ['Browser key', 'info', 'Info'],
    ['Fresh finding', 'candidate', 'Candidate, not triaged yet'],
    ['Debug page', 'candidate', 'Candidate, blocked by AI review: likely false positive'],
    ['Old CVE', 'excluded', 'Excluded'],
  ]
  for (const [name, disposition, title] of want) {
    const chip = chipOf(page, name)
    await expect(chip).toHaveAttribute('data-disposition', disposition)
    await expect(chip).toHaveAttribute('title', new RegExp(`^${title.replace(/[()]/g, '\\$&')}`))
  }
})

test('Board: the disposition filter narrows the list, and Any restores it', async ({ page }) => {
  await openBoard(page)
  const select = page.getByRole('combobox', { name: 'Disposition' })
  await expect(select.locator('option', { hasText: 'Candidate (3)' })).toHaveCount(1)
  await select.selectOption('candidate')
  const chips = page.locator('tbody [data-disposition]')
  await expect(chips).toHaveCount(3)
  for (const d of await chips.evaluateAll(els => els.map(e => e.getAttribute('data-disposition')))) {
    expect(d).toBe('candidate')
  }
  await select.selectOption('')
  await expect(chips).toHaveCount(ROWS.length)
})

test('Board: the detail panel names the disposition above the tier rule', async ({ page }) => {
  await openBoard(page)
  await page.getByRole('button', { name: 'Outdated server banner' }).click()
  const panel = page.getByRole('complementary', { name: 'Finding details' })
  await expect(panel.getByTestId('disposition-line'))
    .toHaveText('Disposition: Candidate, blocked by credible, with impact worth planning for')
})

test('Board: at 390 px the chip collapses to its icon and keeps its tooltip', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await openBoard(page)
  const chip = chipOf(page, 'Outdated server banner')
  await chip.scrollIntoViewIfNeeded()
  await expect(chip.locator('svg')).toBeVisible()
  await expect(chip.locator('span')).toBeHidden()
  await expect(chip).toHaveAttribute('title', 'Candidate, blocked by credible, with impact worth planning for')
})

test('Board: on the project itself, every live row has a chip', async ({ page }) => {
  await openBoard(page, false)
  const rows = page.locator('tbody tr')
  await expect(rows.first()).toBeVisible()
  const n = await rows.count()
  await expect(page.locator('tbody tr [data-disposition]')).toHaveCount(n)
  for (const title of await page.locator('tbody [data-disposition]').evaluateAll(
    els => els.map(e => e.getAttribute('title') ?? ''))) {
    expect(title.length).toBeGreaterThan(0)
  }
})

// Plan 10.5: a v3.10 run stores the answer, and its blocker names a gate.
const GATE_BLOCKER = /, blocked by (not reachable now|shared edge|failed its control check|no impact shown|unknown: (reachable now|attributed|controlled|impactful)|AI review: likely false positive)$/
const EXPECT_STORED = process.env.REDAMON_EXPECT_STORED === '1'

test('Board: the blocker a run stored is shown over the tier rule', async ({ page }) => {
  const stored = { ...ROWS[1], id: 'e2e-stored', name: 'Banner on a CDN edge',
    triage_disposition: 'candidate', triage_blocker: 'shared edge' }
  await openBoard(page, true, [stored])
  await expect(chipOf(page, 'Banner on a CDN edge')).toHaveAttribute('title', /^Candidate, blocked by shared edge/)
  await page.getByRole('button', { name: 'Banner on a CDN edge' }).click()
  await expect(page.getByRole('complementary', { name: 'Finding details' }).getByTestId('disposition-line'))
    .toHaveText('Disposition: Candidate, blocked by shared edge')
})

test('Board: on a project a v3.10 run scored, every candidate names the gate that holds it', async ({ page }) => {
  test.skip(!EXPECT_STORED, 'set REDAMON_EXPECT_STORED=1 after a v3.10 Priority Board run')
  await openBoard(page, false)
  const titles = await page.locator('tbody [data-disposition="candidate"]').evaluateAll(
    els => els.map(e => e.getAttribute('title') ?? ''))
  expect(titles.length).toBeGreaterThan(0)
  for (const title of titles) expect(title).toMatch(GATE_BLOCKER)
})

test('Report: the top summary leads with disposition, and severity is relabelled', async ({ page, playwright, baseURL }) => {
  if (REPORT_HTML) {
    await page.setContent(readFileSync(REPORT_HTML, 'utf8'))
  } else {
    const api = await playwright.request.newContext({
      baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
    })
    const reports = await (await api.get(`/api/projects/${PROJECT}/reports`)).json() as { id: string }[]
    await api.dispose()
    test.skip(!Array.isArray(reports) || reports.length === 0, 'no report generated for this project yet')
    await page.goto(`/api/projects/${PROJECT}/reports/${reports[0].id}`)
  }
  const summary = page.locator('#executive-summary')
  const disposition = summary.getByTestId('disposition-summary')
  await expect(disposition).toBeVisible()
  for (const label of ['Reportable', 'Candidate', 'Info']) {
    await expect(disposition.getByText(label, { exact: true })).toBeVisible()
  }
  if (EXPECT_CANDIDATES) {
    await expect(disposition.getByTestId('disposition-candidate')).toHaveText(EXPECT_CANDIDATES)
  }
  await expect(summary.getByText('Scanner severity (not yet verified)').first()).toBeVisible()
  await expect(page.locator('#risk-summary').getByText('Scanner severity (not yet verified)')).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  expect(await disposition.evaluate(el => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(0)
})
