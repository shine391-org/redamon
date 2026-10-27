import { test, expect, type Page } from '@playwright/test'
import { mintToken, signIn } from './auth'

/**
 * Plan 11: an IP's ownership tag on the two read paths people use.
 *
 * - The node drawer: the graph is served by the test (one IP node), so the
 *   tagged and the untagged states are on screen whatever the project holds,
 *   and the line wraps in a 390 px drawer.
 * - The report: rendered on the server from the graph, so stubbing a browser
 *   request cannot reach it. The test generates a report for
 *   REDAMON_TAGGED_PROJECT (the FP lab's `e2e_fp.py --ip-ownership` project: .32
 *   a shared edge, .31 unknown) and for REDAMON_UNTAGGED_PROJECT (an IP-mode
 *   project scanned before plan 11, whose IPs carry no tag), and reads the IP
 *   Target Map's Ownership column. Each report test skips when its project id
 *   is not set, or when the user has no "Report narratives" model: the app
 *   refuses to generate a report without one, and choosing it is the user's call
 *   (each report then spends tokens on their keys).
 *
 * Requires the stack (the built webapp image). The drawer needs any project the
 * user owns (REDAMON_PROJECT, else the tagged one). Run:
 *   REDAMON_USER=<owner id> REDAMON_TAGGED_PROJECT=<id> REDAMON_UNTAGGED_PROJECT=<id> \
 *     npx playwright test ipOwnership
 */

const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'
const TAGGED = process.env.REDAMON_TAGGED_PROJECT || ''
const UNTAGGED = process.env.REDAMON_UNTAGGED_PROJECT || ''
const DRAWER_PROJECT = process.env.REDAMON_PROJECT || TAGGED || '9417780d1f864e928fbe9091a'
const EDGE = '192.88.94.32'
const PLAIN = '192.88.94.31'

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

/** One IP in a 2D graph, so a click on the fitted canvas's centre opens its drawer. */
async function openIp(page: Page, properties: Record<string, unknown>) {
  const prefs = { graphView: { [DRAWER_PROJECT]: { is3D: false, showLabels: true, renderEnabled: true } } }
  await page.route('**/api/user/preferences', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(prefs) }))
  await page.route('**/api/graph?projectId=*', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      projectId: DRAWER_PROJECT,
      nodes: [{ id: 'ip1', name: EDGE, type: 'IP', properties: { address: EDGE, version: 'ipv4', ...properties } }],
      links: [],
    }) }))
  await page.goto(`/graph?project=${DRAWER_PROJECT}`)
  await page.waitForLoadState('networkidle')
  await page.getByTitle('Fit all nodes').click()
  await page.waitForTimeout(800)
  const canvas = page.locator('canvas').first()
  const box = (await canvas.boundingBox())!
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2)
  const row = page.getByTestId('drawer-ownership')
  await expect(row).toBeVisible()
  return row
}

const SHARED_EDGE = {
  ownership: 'shared_edge', cdn_name: 'cloudflare', is_cdn: true, current_dns_names: 0,
  ownership_reasons: ["a scanner's CDN check named an edge CDN", 'default certificate covers no target domain'],
  default_cert_names: ['cloudflare inc ecc ca-3'],
}

test('Drawer: an IP says whose it is, and the raw keys leave the property list', async ({ page }) => {
  const row = await openIp(page, SHARED_EDGE)
  await expect(row).toContainText('Ownership')
  await expect(row).toContainText(
    "Shared edge (Cloudflare): a scanner's CDN check named an edge CDN; default certificate covers no target domain")
  await expect(page.getByText('ownership_reasons', { exact: true })).toHaveCount(0)
  await expect(page.getByText('default_cert_names', { exact: true })).toHaveCount(1)
})

test('Drawer: an IP no scan attributed yet reads "not checked yet"', async ({ page }) => {
  const row = await openIp(page, {})
  await expect(row).toContainText('not checked yet')
})

test('Drawer: the line wraps inside a 390 px drawer', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const row = await openIp(page, SHARED_EDGE)
  const overflow = await row.evaluate(el => el.scrollWidth - el.clientWidth)
  expect(overflow).toBeLessThanOrEqual(0)
  const value = row.getByText(/Shared edge \(Cloudflare\)/)
  const lines = await value.evaluate(el => el.getBoundingClientRect().height / parseFloat(getComputedStyle(el).lineHeight || '16'))
  expect(lines).toBeGreaterThan(1.5)
})

/** The IP Target Map's rows as {ip: ownership cell}, from a freshly generated report. */
async function ownershipColumn(page: Page, baseURL: string, project: string) {
  const api = await page.context().request
  const headers = { cookie: `redamon-auth=${mintToken(USER)}`, 'content-type': 'application/json' }
  const created = await api.post(`${baseURL}/api/projects/${project}/reports`, { headers, data: {} })
  const body = await created.text()
  test.skip(created.status() === 409 && body.includes('"model_required"'),
    'no "Report narratives" model is set for this user, so the app generates no report')
  expect(created.status(), body).toBe(201)
  const { id } = await created.json()
  await page.goto(`/api/projects/${project}/reports/${id}`)
  const table = page.locator('#scope table', { hasText: 'IP Address' })
  await expect(table.locator('thead th')).toContainText(['IP Address', 'Version', 'Hostnames', 'CDN', 'Ownership', 'Open Ports'])
  const cells: Record<string, string> = {}
  for (const row of await table.locator('tbody tr').all()) {
    const td = row.locator('td')
    cells[(await td.nth(0).innerText()).trim()] = (await td.nth(4).innerText()).trim()
  }
  return cells
}

test('Report: the IP Target Map names each IP\'s ownership', async ({ page, baseURL }) => {
  test.skip(!TAGGED, 'REDAMON_TAGGED_PROJECT is not set')
  const cells = await ownershipColumn(page, baseURL!, TAGGED)
  expect(cells[EDGE]).toBe('Shared edge')
  expect(cells[PLAIN]).toBe('Unknown')
})

test('Report: an IP from a scan before IP attribution has an empty cell, never "Unknown"', async ({ page, baseURL }) => {
  test.skip(!UNTAGGED, 'REDAMON_UNTAGGED_PROJECT is not set')
  const cells = await ownershipColumn(page, baseURL!, UNTAGGED)
  expect(Object.keys(cells).length).toBeGreaterThan(0)
  for (const [ip, cell] of Object.entries(cells)) expect(cell, ip).toBe('')
})
