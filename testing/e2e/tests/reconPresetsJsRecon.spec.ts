import { test, expect, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * JS recon is no scan module (plan 06.7), driven through the real project form.
 *
 * Six built-in presets listed "js_recon" in scanModules, but the pipeline runs
 * JS recon on jsReconEnabled alone. A built-in preset now switches it on by
 * that flag and lists no such module, and a preset saved before the change,
 * which still lists one, must keep loading and saving: the entry does nothing,
 * and refusing it would strand every older preset and project.
 *
 * Requires the stack up and the webapp image built, and a project the user
 * owns (it is overwritten by the presets loaded here):
 *   cd testing/e2e && REDAMON_PROJECT=<id> REDAMON_USER=<ownerId> npx playwright test reconPresetsJsRecon
 */

const PROJECT = process.env.REDAMON_PROJECT || ''
const USER = process.env.REDAMON_USER || ''
const OLD_MODULES = ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon']

const cookie = () => ({ cookie: `redamon-auth=${mintToken(USER)}` })

test.skip(!PROJECT || !USER, 'set REDAMON_PROJECT and REDAMON_USER to a project the user owns')

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

async function readRow(request: any, baseURL: string): Promise<Record<string, unknown>> {
  const res = await request.get(`${baseURL}/api/projects/${PROJECT}`, { headers: cookie() })
  expect(res.ok(), `GET project -> ${res.status()}`).toBeTruthy()
  return await res.json()
}

/** Click a card's button (built-in presets say Select, saved ones Load),
 *  confirm the replacement, and wait for the save. */
async function selectAndConfirm(page: Page, cardName: string, button: 'Select' | 'Load') {
  const card = page.getByRole('heading', { name: cardName, exact: true })
    // The card itself: its class token ends in "__card" (not __cardHeader).
    .locator('xpath=ancestor::div[contains(concat(@class, " "), "__card ")][1]')
  const saved = page.waitForResponse(r => r.url().endsWith(`/api/projects/${PROJECT}`)
    && r.request().method() === 'PUT')
  await card.getByRole('button', { name: button, exact: true }).click()
  await page.getByRole('button', { name: /^Replace (and save|settings)$/ }).click()
  const res = await saved
  expect(res.ok(), `preset save PUT -> ${res.status()}`).toBeTruthy()
}

test('a built-in preset runs JS recon by its switch, with no js_recon module', async ({ page, request, baseURL }) => {
  // JS recon off first: the result then shows the preset switching it on,
  // and a preset left applied by an earlier run is no longer "Applied".
  const before = await readRow(request, baseURL!)
  const off = await request.put(`${baseURL}/api/projects/${PROJECT}`, {
    headers: { ...cookie(), 'content-type': 'application/json' },
    data: { ...before, jsReconEnabled: false },
  })
  expect(off.ok(), `reset PUT -> ${off.status()}`).toBeTruthy()

  await page.goto(`/projects/${PROJECT}/settings`)
  await page.getByRole('button', { name: 'Recon Preset', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Recon Presets' })).toBeVisible()
  await selectAndConfirm(page, 'JS Secret Miner', 'Select')

  const row = await readRow(request, baseURL!)
  expect(row.scanModules).not.toContain('js_recon')
  expect(row.scanModules).toEqual(expect.arrayContaining(['http_probe', 'resource_enum']))
  expect(row.jsReconEnabled).toBe(true)
})

test('an old preset that still lists js_recon loads and saves unchanged', async ({ page, request, baseURL }) => {
  const name = `Old JS preset ${Date.now()}`
  const created = await request.post(`${baseURL}/api/presets`, {
    headers: { ...cookie(), 'content-type': 'application/json' },
    data: { name, description: 'saved before js_recon left the scan modules',
            settings: { scanModules: OLD_MODULES, jsReconEnabled: true } },
  })
  expect(created.status(), 'the old preset is accepted on save').toBe(201)
  const { id } = await created.json()
  try {
    await page.goto(`/projects/${PROJECT}/settings`)
    await page.getByRole('button', { name: 'Load Preset' }).click()
    await selectAndConfirm(page, name, 'Load')

    const row = await readRow(request, baseURL!)
    expect(row.scanModules).toEqual(OLD_MODULES)
    expect(row.jsReconEnabled).toBe(true)
  } finally {
    await request.delete(`${baseURL}/api/presets/${id}`, { headers: cookie() })
  }
})
