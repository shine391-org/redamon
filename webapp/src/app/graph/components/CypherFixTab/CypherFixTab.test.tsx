/**
 * The CypherFix tab says when the remediation list, a dismiss or a delete failed
 * (G-38, G-39).
 *
 * A failed load with no filter set showed the empty state ("Start triage") over
 * remediations that exist, and Dismiss / Delete used `mutate`, which never
 * throws: a refused delete still navigated back as if it had worked.
 *
 * Run: npx vitest run src/app/graph/components/CypherFixTab/CypherFixTab.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({
  remediations: {} as Record<string, unknown>,
  alertError: vi.fn(),
}))

vi.mock('@/hooks', () => ({ useRemediations: () => h.remediations }))
vi.mock('@/hooks/useProjects', () => ({ useProjectById: () => ({ data: null }) }))
vi.mock('@/components/ui', () => ({ useAlertModal: () => ({ alertError: h.alertError }) }))
vi.mock('./EmptyState/EmptyState', () => ({ EmptyState: () => <div>EMPTY STATE</div> }))
vi.mock('./TriageProgress/TriageProgress', () => ({ TriageProgress: () => null }))
vi.mock('@/components/triage/TriageRunBanner', () => ({ TriageRunBanner: () => null }))
vi.mock('./DiffViewer/DiffViewer', () => ({ DiffViewer: () => null }))
vi.mock('./RemediationDashboard/RemediationDashboard', () => ({
  RemediationDashboard: (p: { error: Error | null; onSelectRemediation: (r: unknown) => void;
    onDismiss: (id: string) => void }) => (
    <div>
      <div>DASHBOARD {p.error ? `error: ${p.error.message}` : ''}</div>
      <button onClick={() => p.onSelectRemediation({ id: 'r1', title: 'Fix' })}>open</button>
      <button onClick={() => p.onDismiss('r1')}>dismiss</button>
    </div>
  ),
}))
vi.mock('./RemediationDetail/RemediationDetail', () => ({
  RemediationDetail: (p: { onDelete: (id: string) => void }) => (
    <div>
      <div>DETAIL</div>
      <button onClick={() => p.onDelete('r1')}>delete</button>
    </div>
  ),
}))

import { CypherFixTab } from './CypherFixTab'

const TRIAGE = { status: 'connected', currentPhase: null, progress: 0, findings: [], thinking: '',
  error: null, notice: null, startTriage: vi.fn(), stopTriage: vi.fn(), disconnect: vi.fn() }

function renderTab() {
  return render(
    <CypherFixTab projectId="p1" userId="u1" triage={TRIAGE as never} showTriageProgress={false}
      onStartTriage={vi.fn()} onCloseTriageProgress={vi.fn()} />,
  )
}

const refused = new ApiError({ reason: 'Failed to delete remediation', status: 404, code: 'not_found' })

beforeEach(() => {
  h.alertError.mockReset().mockResolvedValue(undefined)
  h.remediations = {
    remediations: [{ id: 'r1', title: 'Fix' }], isLoading: false, error: null, refetch: vi.fn(),
    updateRemediationAsync: vi.fn().mockResolvedValue({}),
    deleteRemediationAsync: vi.fn().mockResolvedValue(undefined),
  }
})
afterEach(cleanup)

describe('CypherFix tab failures', () => {
  test('a failed load shows the error, not the empty state', () => {
    h.remediations = { ...h.remediations, remediations: [],
      error: new ApiError({ reason: 'Failed to fetch remediations', status: 500, code: 'P1001' }) }
    renderTab()
    expect(screen.queryByText('EMPTY STATE')).toBeNull()
    expect(screen.getByText('DASHBOARD error: Failed to fetch remediations (P1001 · HTTP 500)')).toBeInTheDocument()
  })

  test('a project with no remediations still gets the empty state', () => {
    h.remediations = { ...h.remediations, remediations: [] }
    renderTab()
    expect(screen.getByText('EMPTY STATE')).toBeInTheDocument()
  })

  test('a refused delete is shown with its cause and the detail stays open', async () => {
    h.remediations = { ...h.remediations, deleteRemediationAsync: vi.fn().mockRejectedValue(refused) }
    renderTab()
    fireEvent.click(screen.getByText('open'))
    fireEvent.click(screen.getByText('delete'))
    await waitFor(() => expect(h.alertError).toHaveBeenCalledWith('Failed to delete remediation (not_found · HTTP 404)', 'Delete'))
    expect(screen.getByText('DETAIL')).toBeInTheDocument()
  })

  test('a delete that worked goes back to the dashboard', async () => {
    renderTab()
    fireEvent.click(screen.getByText('open'))
    fireEvent.click(screen.getByText('delete'))
    await waitFor(() => expect(screen.getByText(/DASHBOARD/)).toBeInTheDocument())
    expect(h.alertError).not.toHaveBeenCalled()
  })

  test('a refused dismiss is shown with its cause', async () => {
    h.remediations = { ...h.remediations, updateRemediationAsync: vi.fn().mockRejectedValue(
      new ApiError({ reason: 'Failed to update remediation', status: 400 })) }
    renderTab()
    fireEvent.click(screen.getByText('dismiss'))
    await waitFor(() => expect(h.alertError).toHaveBeenCalledWith('Failed to update remediation (HTTP 400)', 'Dismiss'))
  })
})
