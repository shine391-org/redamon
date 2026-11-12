import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { render, screen, fireEvent, cleanup, within, waitFor } from '@testing-library/react'
import { GraphToolbar } from './GraphToolbar'
import { boundedDiagnosticValue } from './ReconDiagnostics'

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let data: Record<string, unknown>
let manifest: Record<string, unknown>
let refusal = false
let readError = false
let networkError = false
const fixture = () => ({ status: 'ready', run_id: 'fixture-run', group_id: 'fixture-group', is_history: false,
  inventory: { total: 0, sources: { openapi: 3 }, provenance: ['declared_only'], validation: { unknown: 2 }, reasons: ['unvalidated source'] },
  selection: { saved: ['cve'], effective: [], removed: ['cve'], deferred: 2, reasons: ['empty selection is not clean'], compatibility: 1 },
  checkpoint: { scope: 'group6_phase_a', counts: { completed: 0, deferred: 2, uncertain: 1 },
    budgets: { per_group: 0, per_tool: 2 }, entries: [{ tool: 'nuclei', state: 'deferred', reason: 'budget exhausted' }],
    continuation: { supported: true, eligible: true, run_id: 'fixture-run' } },
})

beforeEach(() => {
  data = fixture(); manifest = { status: 'known', manifest: { run_id: 'fixture-run', group_id: 'fixture-group', decisions: ['<img src=x onerror=alert(1)>'], authorization: 'never-render-fixture' } }
  refusal = false; readError = false; networkError = false
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    if (networkError) throw new Error('offline fixture')
    if (url.endsWith('/continue')) {
      expect(init?.method).toBe('POST')
      return refusal ? json({ error: 'Continuation refused: revision changed', code: 'revision_conflict' }, 409) : json({ status: 'started' })
    }
    if (readError) return json({ error: 'Artifacts unavailable', code: 'offline_fixture' }, 503)
    return json(url.endsWith('/plan-manifest') ? manifest : data)
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
function draw(extra = {}) {
  render(<GraphToolbar projectId="fixture-project" is3D={false} showLabels onToggle3D={vi.fn()} onToggleLabels={vi.fn()} {...extra} />)
}
async function open() {
  fireEvent.click(screen.getByRole('button', { name: 'Recon diagnostics' }))
  await waitFor(() => expect(screen.queryByText('Loading diagnostics…')).toBeNull())
  return screen.getByRole('dialog', { name: 'Recon diagnostics' })
}
const posts = () => vi.mocked(fetch).mock.calls.filter(([, init]) => init?.method === 'POST')
const continueButton = () => screen.getByRole('button', { name: 'Continue deferred Group 6 Phase A work' })

test('toolbar reaches meaningful inventory/selection/checkpoint/manifest views even without coverage status', async () => {
  draw()
  expect(fetch).not.toHaveBeenCalled()
  const dialog = await open()
  expect(within(dialog).getByText('declared_only')).toBeVisible()
  expect(within(dialog).getByText('unvalidated source')).toBeVisible()
  expect(within(dialog).getByText('empty selection is not clean')).toBeVisible()
  expect(within(dialog).getByText('budget exhausted')).toBeVisible()
  expect(within(dialog).getByText('<img src=x onerror=alert(1)>')).toBeVisible()
  expect(dialog.querySelector('img')).toBeNull()
  expect(dialog.textContent).not.toContain('never-render-fixture')
  expect(within(dialog).getByText(/Run IDs match/)).toBeVisible()
  const inventory = within(dialog).getByRole('region', { name: 'Discovery inventory' })
  expect(within(inventory).getByText('0')).toBeVisible()
  expect(continueButton()).toBeEnabled()
  expect(posts()).toHaveLength(0)
})

test('continuation requires click then confirmation, supports cancel and reports server refusal with status/code', async () => {
  refusal = true
  draw(); await open()
  fireEvent.click(continueButton())
  expect(posts()).toHaveLength(0)
  fireEvent.click(screen.getByRole('button', { name: 'Cancel continuation' }))
  expect(posts()).toHaveLength(0)
  fireEvent.click(continueButton())
  fireEvent.click(screen.getByRole('button', { name: 'Confirm continuation' }))
  await screen.findByText(/revision_conflict.*HTTP 409/)
  expect(posts()).toHaveLength(1)
  expect(JSON.parse(String(posts()[0][1]?.body))).toEqual({ run_id: 'fixture-run' })
  expect(continueButton()).toBeDisabled()
})

test('successful confirmation dispatches once and never automatically repeats', async () => {
  draw(); await open()
  fireEvent.click(continueButton())
  fireEvent.click(screen.getByRole('button', { name: 'Confirm continuation' }))
  await screen.findByText(/Continuation request accepted/)
  expect(posts()).toHaveLength(1)
})

test('stale eligibility is rechecked and refuses dispatch', async () => {
  draw(); await open()
  fireEvent.click(continueButton())
  data = { ...fixture(), run_id: 'different', checkpoint: { scope: 'group6_phase_a', continuation: { supported: true, eligible: false, reason: 'window closed' } } }
  fireEvent.click(screen.getByRole('button', { name: 'Confirm continuation' }))
  await screen.findByText(/eligibility or run\/group changed/)
  expect(posts()).toHaveLength(0)
  expect(continueButton()).toBeDisabled()
})

test.each([
  { status: 'unknown', reason: 'no artifacts', inventory: null, selection: null, checkpoint: null },
  { ...fixture(), checkpoint: { scope: 'group6_phase_a', continuation: { supported: false, eligible: true } } },
  { ...fixture(), checkpoint: { scope: 'other', continuation: { supported: true, eligible: true } } },
  { ...fixture(), checkpoint: { scope: 'group6_phase_a', continuation: { supported: true, eligible: 'true' } } },
])('unknown/unsupported/malformed eligibility cannot dispatch', async value => {
  data = value
  draw(); const dialog = await open()
  expect(within(dialog).getAllByText('Unknown / not recorded').length).toBeGreaterThan(0)
  expect(continueButton()).toBeDisabled()
  expect(posts()).toHaveLength(0)
})

test('historical graph warns about latest-run APIs and disables continuation', async () => {
  draw({ selectedVersionId: 'old-version' }); await open()
  expect(screen.getByText(/You are viewing a historical graph/)).toBeVisible()
  expect(continueButton()).toBeDisabled()
})

test.each(['http', 'network'])('%s errors remain visible and unknown, not zeros', async kind => {
  readError = kind === 'http'; networkError = kind === 'network'
  draw(); const dialog = await open()
  expect(within(dialog).getAllByRole('alert')).toHaveLength(2)
  expect(within(dialog).getAllByText('Unknown / not recorded').length).toBeGreaterThan(0)
  expect(continueButton()).toBeDisabled()
  expect(posts()).toHaveLength(0)
})

test('manifest and diagnostics from different runs are not silently combined', async () => {
  manifest = { status: 'unknown', reason: 'no pointer' }
  draw(); await open()
  expect(screen.getByText(/Run correlation unknown or different/)).toBeVisible()
  expect(screen.getByText('no pointer')).toBeVisible()
})

test('untrusted structured values are bounded and credentials/raw headers removed', () => {
  const value = boundedDiagnosticValue({ headers: { value: 'fixture-header' }, auth_profile: 'fixture-auth',
    rows: Array.from({ length: 500 }, (_, n) => `row-${n}`),
    reason: 'Bearer fixture-bearer https://name:pass@fixture.test/path?token=fixture-token',
    text: 'x'.repeat(5000), count: 0, absent: null })
  const encoded = JSON.stringify(value)
  expect(encoded).not.toContain('fixture-header'); expect(encoded).not.toContain('fixture-auth')
  expect(encoded).not.toContain('fixture-bearer'); expect(encoded).not.toContain('fixture-token')
  expect(encoded).not.toContain('name:pass'); expect(encoded).not.toContain('row-499')
  expect(encoded).toContain('more entries omitted'); expect(encoded.length).toBeLessThan(4000)
})

test('coverage toolbar shows known zero vs missing unknown and honest module labels', () => {
  draw({ reconCoverageSummary: { js_recon: { recorded: true, complete: 0 }, other_module: { recorded: true, failed: 2 }, empty: null } })
  expect(screen.getByText('complete: 0')).toBeVisible()
  expect(screen.getAllByText('partial: unknown')).toHaveLength(2)
  expect(screen.getByText('other_module:')).toBeVisible()
})
