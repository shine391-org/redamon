import { test, expect, type APIRequestContext, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * The seven route exposure v2 switches, driven through the real settings UI
 * (plan §22.3, per-parameter protocol for a toggle): flip each on the Route
 * Exposure card, save, check the PUT carried it and the stored value moved,
 * reopen and see the flipped state, flip back, save, and check the default is
 * stored again. No console error may come from the form. A screenshot of the
 * flipped card lands in the lab's gitignored screenshots folder.
 *
 * A throwaway project on a .test domain, deleted afterwards. Requires the stack up
 * and the webapp image built. Run:
 *   cd testing/e2e && npx playwright test routeExposureV2Toggles
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const SHOTS = '../guinea_pigs/route_exposure_lab/reports/screenshots/v2'

const SWITCHES = [
  { field: 'routeExposureSiblings', label: 'Sibling routes', byDefault: true },
  { field: 'routeExposureFrameworkSeeds', label: 'Framework paths', byDefault: true },
  { field: 'routeExposureFollowCatalogs', label: 'Follow route catalogs', byDefault: true },
  { field: 'routeExposureGitWalk', label: 'Git walk proof', byDefault: true },
  { field: 'routeExposureCrossHost', label: 'Cross-host', byDefault: false },
  { field: 'routeExposureCorsRider', label: 'Cross-origin (CORS)', byDefault: true },
  { field: 'routeExposureCacheRider', label: 'Cacheable logged-in content', byDefault: true },
] as const

let projectId = ''
let api: APIRequestContext

test.beforeAll(async ({ playwright, baseURL }) => {
  api = await playwright.request.newContext({
    baseURL, extraHTTPHeaders: { cookie: `redamon-auth=${mintToken(USER)}` },
  })
  const res = await api.post('/api/projects', {
    data: { name: 'route-exposure-e2e v2-UI (temp)', targetDomain: 'example.test', routeExposureEnabled: true },
  })
  expect(res.ok(), `create project: ${res.status()}`).toBeTruthy()
  projectId = (await res.json()).id
})

test.afterAll(async () => {
  if (projectId) {
    const res = await api.delete(`/api/projects/${projectId}`)
    expect(res.ok(), `delete the throwaway project: ${res.status()}`).toBeTruthy()
  }
  await api?.dispose()
})

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

async function stored(): Promise<Record<string, unknown>> {
  const res = await api.get(`/api/projects/${projectId}`)
  expect(res.ok(), `GET project -> ${res.status()}`).toBeTruthy()
  return res.json()
}

async function openRouteExposure(page: Page) {
  await page.goto(`/projects/${projectId}/settings`)
  await expect(page.getByRole('heading', { name: /Project Settings/i })).toBeVisible({ timeout: 30_000 })
  await page.locator('[title="Tab view"]').first().click()
  await page.getByRole('button', { name: 'Vulnerability Scanning', exact: true }).first().click()
  await expect(page.getByRole('switch', { name: 'Enable Route Exposure' })).toBeVisible({ timeout: 15_000 })
}

function control(page: Page, label: string) {
  return page.getByRole('switch', { name: label, exact: true })
}

async function save(page: Page): Promise<Record<string, unknown>> {
  const btn = page.getByRole('button', { name: 'Update Settings', exact: true }).first()
  await expect(btn, 'Save stayed disabled, so the form never saw the change').toBeEnabled()
  const [response] = await Promise.all([
    page.waitForResponse(r => r.request().method() === 'PUT' &&
      r.url().includes(`/api/projects/${projectId}`), { timeout: 20_000 }),
    btn.click(),
  ])
  expect(response.status(), `PUT -> ${response.status()}`).toBeLessThan(400)
  return response.request().postDataJSON()
}

test('every v2 switch flips, persists, reloads and flips back', async ({ page }) => {
  test.setTimeout(180_000)
  const errors: string[] = []
  page.on('console', msg => { if (msg.type() === 'error') errors.push(msg.text()) })
  page.on('pageerror', err => errors.push(String(err)))
  const notFound: string[] = []
  page.on('response', r => { if (r.status() === 404) notFound.push(new URL(r.url()).pathname) })

  const initial = await stored()
  for (const s of SWITCHES) {
    expect(initial[s.field], `${s.field} default`).toBe(s.byDefault)
  }

  await openRouteExposure(page)
  for (const s of SWITCHES) {
    const sw = control(page, s.label)
    await expect(sw, s.label).toHaveAttribute('aria-checked', String(s.byDefault))
    await sw.click()
    await expect(sw).toHaveAttribute('aria-checked', String(!s.byDefault))
    await sw.scrollIntoViewIfNeeded()
    await page.screenshot({ path: `${SHOTS}/${s.field}.png` })
  }
  let body = await save(page)
  let after = await stored()
  for (const s of SWITCHES) {
    expect(body[s.field], `the PUT never carried ${s.field}`).toBe(!s.byDefault)
    expect(after[s.field], `${s.field} did not persist`).toBe(!s.byDefault)
  }

  await openRouteExposure(page)
  for (const s of SWITCHES) {
    const sw = control(page, s.label)
    await expect(sw, `${s.label} after reload`).toHaveAttribute('aria-checked', String(!s.byDefault))
    await sw.click()
    await expect(sw).toHaveAttribute('aria-checked', String(s.byDefault))
  }
  body = await save(page)
  after = await stored()
  for (const s of SWITCHES) {
    expect(body[s.field], `the PUT never carried ${s.field} back`).toBe(s.byDefault)
    expect(after[s.field], `${s.field} did not return to its default`).toBe(s.byDefault)
  }

  // Saving leaves the form for the graph page, which probes for a recon and a GVM
  // download a never-scanned project does not have. Those 404s are expected;
  // anything else is a failure.
  const probe = new RegExp(`^/api/(recon|gvm)/${projectId}/download$`)
  expect(notFound.filter(p => !probe.test(p)), 'unexpected 404s').toEqual([])
  const real = notFound.length ? errors.filter(e => !e.startsWith('Failed to load resource')) : errors
  expect(real, 'console errors while driving the form').toEqual([])
})
