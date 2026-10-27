import { test, expect, type Page } from '@playwright/test'
import { signIn } from './auth'

/**
 * Plan 09.1: a BaseURL's node drawer shows what JS Recon and Nuclei did on that
 * host, one line per module, in its full, partial and empty states, and the
 * section wraps in a narrow drawer.
 *
 * The graph is served by the test (one stubbed BaseURL), so every state is on
 * screen whatever the project holds; the stamps' writers and the "not scanned"
 * reading (which needs a second, stamped host) are covered by the unit tests
 * and the FP lab run (testing/guinea_pigs/fp_regression_target, plan 09).
 *
 * Requires the stack to be up. Run: npx playwright test nodeDrawerCoverage
 */

const PROJECT = process.env.REDAMON_PROJECT || '9417780d1f864e928fbe9091a'
const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const URL = 'http://192.88.94.20'

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

/** One BaseURL in a 2D graph, so a click on the fitted canvas's centre opens its drawer. */
async function openBaseUrl(page: Page, stamps: Record<string, unknown>) {
  const prefs = { graphView: { [PROJECT]: { is3D: false, showLabels: true, renderEnabled: true } } }
  await page.route('**/api/user/preferences', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(prefs) }))
  await page.route('**/api/graph?projectId=*', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      projectId: PROJECT,
      nodes: [{ id: 'bu1', name: URL, type: 'BaseURL',
                properties: { url: URL, scheme: 'http', host: '192.88.94.20', source: 'http_probe', ...stamps } }],
      links: [],
    }) }))
  await page.goto(`/graph?project=${PROJECT}`)
  await page.waitForLoadState('networkidle')
  await page.getByTitle('Fit all nodes').click()
  await page.waitForTimeout(800)
  const canvas = page.locator('canvas').first()
  const box = (await canvas.boundingBox())!
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2)
  const section = page.getByTestId('coverage-section')
  await expect(section).toBeVisible()
  return section
}

const JS_NUCLEI_DONE = {
  js_recon_status: 'complete', js_recon_inputs: 12, js_recon_outputs: 0,
  js_recon_at: '2026-10-25T08:00:00Z',
  nuclei_status: 'complete', nuclei_inputs: 4, nuclei_outputs: 1,
}

test('one line per module, and the raw stamps only there', async ({ page }) => {
  const section = await openBaseUrl(page, JS_NUCLEI_DONE)
  await expect(section).toContainText('JS analysis')
  await expect(section).toContainText('complete, 12 files, 0 findings')
  await expect(section).toContainText('Nuclei')
  await expect(section).toContainText('complete, 4 URLs, 1 finding')
  await expect(page.getByText('js_recon_status', { exact: true })).toHaveCount(0)
  await expect(page.getByText('nuclei_inputs', { exact: true })).toHaveCount(0)
})

test('a partial and a failed stamp name their reason', async ({ page }) => {
  const section = await openBaseUrl(page, {
    js_recon_status: 'partial', js_recon_inputs: 2, js_recon_outputs: 1, js_recon_reason: 'file cap',
    nuclei_status: 'failed', nuclei_inputs: 0, nuclei_outputs: 0, nuclei_reason: 'runtime cap',
  })
  await expect(section).toContainText('partial (file cap), 2 files, 1 finding')
  await expect(section).toContainText('failed (runtime cap)')
})

test('no stamp anywhere reads "coverage not recorded", never "not scanned"', async ({ page }) => {
  const section = await openBaseUrl(page, {})
  await expect(section.getByText('coverage not recorded')).toHaveCount(2)
  await expect(section.getByText('not scanned by this module')).toHaveCount(0)
})

test('narrow screen: the section wraps inside the drawer', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const section = await openBaseUrl(page, {
    ...JS_NUCLEI_DONE, nuclei_status: 'partial', nuclei_reason: 'runtime cap, nuclei exited 137',
  })
  await expect(section).toContainText('partial (runtime cap, nuclei exited 137), 4 URLs, 1 finding')
  // Read in one frame: the drawer slides in, so two separate boxes can come
  // from two different points of the animation.
  const overflow = await section.evaluate(el => el.scrollWidth - el.clientWidth)
  expect(overflow).toBeLessThanOrEqual(0)
  const lines = await section.getByText(/partial \(runtime cap/).evaluate(el => {
    const { height } = el.getBoundingClientRect()
    return height / parseFloat(getComputedStyle(el).lineHeight || '16')
  })
  expect(lines).toBeGreaterThan(1.5)
})
