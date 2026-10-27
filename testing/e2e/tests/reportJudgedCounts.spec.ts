import { test, expect, type Page } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { mintToken, signIn } from './auth'

/**
 * What the Priority Board set aside, on the two deliverable surfaces.
 *
 * A finding a person marked False positive, and one the board resolved, leave
 * the severity counts; one only an AI review flagged stays in them. Each
 * surface says how many of each, on its own line, hides a zero line, and shows
 * nothing at all when the board's state could not be read.
 *
 * Insights is served its vulnerability data by the test, so every case renders
 * whatever the project holds. The report is rendered on the server, so stubbing
 * a browser request could not exercise it: the test opens REDAMON_REPORT_HTML
 * when set (a report rendered from the project with gatherReportData and
 * generateReportHtml, as the report route does), else the project's newest
 * stored report. Set REDAMON_EXPECT_PERSON_FP to the number of findings a
 * person marked False positive when that report was rendered.
 *
 * Requires the stack (the built webapp image). Run:
 *   REDAMON_PROJECT=<id> REDAMON_USER=<owner id> npx playwright test reportJudgedCounts
 */

const PROJECT = process.env.REDAMON_PROJECT || ''
const USER = process.env.REDAMON_USER || ''
const EXPECT_PERSON_FP = process.env.REDAMON_EXPECT_PERSON_FP
const REPORT_HTML = process.env.REDAMON_REPORT_HTML

const VULNS = {
  severityDistribution: [{ severity: 'high', count: 3 }, { severity: 'medium', count: 2 }],
  vulnTypes: [], findings: [], cvssHistogram: [], cveSeverity: [], cveChains: [], exploits: [],
  githubSecrets: { repos: 0, secrets: 0, sensitiveFiles: 0 }, gvmRemediation: [],
}

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

async function openInsights(page: Page, judged: unknown) {
  await page.route('**/api/analytics/vulnerabilities*', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...VULNS, judged }) }),
  )
  await page.goto(`/insights?project=${PROJECT}`)
  await expect(page.getByText('Scanner severity (not yet verified)').first()).toBeVisible()
}

const note = (page: Page) => page.getByRole('list', { name: 'Findings the Priority Board judged' })

test('Insights: one line per count, saying whether it is still counted', async ({ page }) => {
  await openInsights(page, { personFalsePositive: 1, resolved: 2, aiFlagged: 3 })
  await expect(note(page).getByRole('listitem')).toHaveText([
    '1 judged false positive by a person: not counted above',
    '2 resolved (fixed, gone, inactive): not counted above',
    '3 flagged as likely false positive by AI review: still counted above',
  ])
})

test('Insights: a zero line is hidden, and an unreadable count shows nothing', async ({ page }) => {
  await openInsights(page, { personFalsePositive: 0, resolved: 2, aiFlagged: 0 })
  await expect(note(page).getByRole('listitem')).toHaveCount(1)

  await page.unrouteAll()
  await openInsights(page, null)
  await expect(note(page)).toHaveCount(0)
})

test('Insights: at 390 px the lines stack inside the screen', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await openInsights(page, { personFalsePositive: 1, resolved: 2, aiFlagged: 3 })
  const list = note(page)
  await list.scrollIntoViewIfNeeded()
  await expect(list.getByRole('listitem')).toHaveCount(3)
  const box = await list.boundingBox()
  expect(box).not.toBeNull()
  expect(box!.x).toBeGreaterThanOrEqual(0)
  expect(box!.x + box!.width).toBeLessThanOrEqual(390)
  const overflow = await list.evaluate(el => el.scrollWidth - el.clientWidth)
  expect(overflow).toBeLessThanOrEqual(0)
})

test('Report: the board lines are printed in the scope table', async ({ page, playwright, baseURL }) => {
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
  const scope = page.locator('#scope')
  await expect(scope).toBeVisible()
  const row = scope.locator('tr', { hasText: 'Judged false positive by a person' })
  if (EXPECT_PERSON_FP && Number(EXPECT_PERSON_FP) > 0) {
    await expect(row).toHaveText(
      new RegExp(`Judged false positive by a person\\s*${EXPECT_PERSON_FP} finding\\(s\\) excluded from this report`))
  } else if (EXPECT_PERSON_FP === '0') {
    await expect(row).toHaveCount(0)
  }
  // An AI-only false positive is never worded as excluded.
  const ai = scope.locator('tr', { hasText: 'Flagged as likely false positive by AI review' })
  if (await ai.count()) await expect(ai).toContainText('still counted in this report')

  await page.setViewportSize({ width: 390, height: 844 })
  const table = scope.locator('table', { hasText: 'Total Graph Nodes' })
  expect(await table.evaluate(el => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(0)
  if (await row.count()) {
    const box = await row.boundingBox()
    expect(box!.x + box!.width).toBeLessThanOrEqual(390)
  }
})
