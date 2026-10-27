import { test, expect, type Page } from '@playwright/test'
import { signIn } from './auth'

/**
 * Plan 05: the secret validation states and the public-client-key flag, as
 * the Red Zone secrets table and the JS Recon table show them.
 *
 * The rows are served by the test (stubbed API data), so every state is on
 * screen whatever the project holds, and no lab key is ever validated against
 * a real provider. What the stub cannot prove, that the routes produce these
 * rows from the graph, is covered by the route tests and the FP lab run.
 *
 * Requires the stack to be up. Run: npx playwright test secretsValidationLabels
 */

const PROJECT = process.env.REDAMON_PROJECT || '9417780d1f864e928fbe9091a'
const USER = process.env.REDAMON_USER || 'cmrzlj3xk0000ob3vo67o3igg'

/** Stored status -> the words a person reads. */
const STATES: [string, string][] = [
  ['validated', 'LIVE'],
  ['unknown', 'could not check'],
  ['rejected', 'rejected'],
  ['format_invalid', 'malformed'],
  ['unvalidated', 'no validator'],
  ['skipped', 'not checked'],
  ['invalid', 'invalid'],
]

test.beforeEach(async ({ context, baseURL }) => {
  await signIn(context, USER, baseURL!)
  await context.addInitScript(() => {
    localStorage.setItem('redamon-v2-onboarding', JSON.stringify({
      version: '2026-03-28-v2', acceptedAt: new Date().toISOString(),
    }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  })
})

function redZoneRow(id: string, extra: Record<string, unknown>) {
  return {
    nodeId: null, origin: 'Secret', id, secretType: 'Generic API Key', valueSample: 'k3x9q2...h9z0',
    matchedText: null, entropy: 4.1, confidence: 'medium', severity: 'medium', publicClientKey: false,
    sourceModule: 'js_recon', sourceUrl: 'http://192.88.94.20/static/js/keys.8c2d.js', secretBaseUrl: null,
    keyType: 'secret', detectionMethod: 'regex', validationStatus: null, baseUrl: 'http://192.88.94.20',
    subdomain: null, jsFileUrl: null, trufflehogSource: null, asset: null, location: null, updatedAt: null,
    ...extra,
  }
}

async function stubRedZone(page: Page, rows: unknown[]) {
  await page.route('**/api/analytics/redzone/secrets*', route =>
    route.fulfill({ status: 200, contentType: 'application/json',
                    body: JSON.stringify({ rows, meta: { totalRows: rows.length } }) }))
}

async function stubJsRecon(page: Page, secrets: unknown[]) {
  const empty = { dependencies: [], source_maps: [], dom_sinks: [], frameworks: [], dev_comments: [],
                  emails: [], ip_addresses: [], dev_references: [], object_references: [],
                  cloud_assets: [], external_domains: [], endpoints: [] }
  await page.route('**/api/js-recon/*/download*', route =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      scan_metadata: { js_files_analyzed: 1 }, secrets, ...empty,
      summary: { total_secrets: secrets.length, total_endpoints: 0, total_findings: 0 },
    }) }))
}

test('Red Zone secrets: each validation state in words', async ({ page }) => {
  await stubRedZone(page, STATES.map(([status], i) => redZoneRow(`s${i}`, { validationStatus: status })))
  await page.goto(`/graph?project=${PROJECT}&table=secrets`)
  await page.waitForLoadState('networkidle')

  const rows = page.locator('tbody tr')
  await expect(rows).toHaveCount(STATES.length)
  for (const [, label] of STATES) {
    await expect(page.locator('tbody').getByText(label, { exact: true }).first()).toBeVisible()
  }
  // The stub serves the rows in the order the route sorts them (validationStatus.ts).
  await expect(rows.first()).toContainText('LIVE')
})

test('Red Zone secrets: a TruffleHog credential checked and dead reads rejected under either word', async ({ page }) => {
  await stubRedZone(page, [
    redZoneRow('tf-new', { origin: 'MultiscannerFinding', secretType: 'AWS', validationStatus: 'rejected' }),
    redZoneRow('tf-old', { origin: 'MultiscannerFinding', secretType: 'AWS', validationStatus: 'unvalidated' }),
  ])
  await page.goto(`/graph?project=${PROJECT}&table=secrets`)
  await page.waitForLoadState('networkidle')
  await expect(page.locator('tbody').getByText('rejected', { exact: true })).toHaveCount(2)
  await expect(page.locator('tbody').getByText('no validator', { exact: true })).toHaveCount(0)
})

test('Red Zone secrets: a key that is public by design is info with a chip', async ({ page }) => {
  await stubRedZone(page, [
    redZoneRow('pub', { secretType: 'GCP API Key', severity: 'info', publicClientKey: true,
                        validationStatus: 'skipped' }),
    redZoneRow('sec', { secretType: 'Stripe Secret Key', severity: 'critical', validationStatus: 'skipped' }),
  ])
  await page.goto(`/graph?project=${PROJECT}&table=secrets`)
  await page.waitForLoadState('networkidle')
  const pub = page.locator('tbody tr', { hasText: 'GCP API Key' })
  await expect(pub.getByText('public key', { exact: true })).toBeVisible()
  await expect(page.locator('tbody tr', { hasText: 'Stripe Secret Key' }).getByText('public key')).toHaveCount(0)
})

test('JS Recon secrets: each validation state in words', async ({ page }) => {
  await stubJsRecon(page, STATES.map(([status], i) => ({
    nodeId: null, id: `j${i}`, name: 'Generic API Key', severity: 'medium', public_client_key: false,
    redacted_value: 'k3x9q2...h9z0', matched_text: null, category: 'secret',
    source_url: 'http://192.88.94.20/static/js/keys.8c2d.js', confidence: 'medium',
    detection_method: 'regex', validation: { status }, updatedAt: null,
  })))
  await page.goto(`/graph?project=${PROJECT}&table=jsRecon`)
  await page.waitForLoadState('networkidle')
  for (const [, label] of STATES) {
    await expect(page.locator('tbody').getByText(label, { exact: true }).first()).toBeVisible()
  }
})

test('narrow screen: the labels still render', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await stubRedZone(page, [redZoneRow('s1', { validationStatus: 'unknown' })])
  await page.goto(`/graph?project=${PROJECT}&table=secrets`)
  await page.waitForLoadState('networkidle')
  await expect(page.locator('tbody').getByText('could not check', { exact: true })).toBeAttached()
})
