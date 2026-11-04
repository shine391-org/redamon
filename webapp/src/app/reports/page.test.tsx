/**
 * The reports page says when something failed, and why (G-20, G-21, G-22, G-23).
 *
 * Delete used `mutate`, which never throws, so "Report deleted" was toasted
 * whatever happened; a failed list read "No reports generated yet"; a download
 * dropped the route's specific 404 text; a report made without narratives
 * because the agent was down was announced like any other.
 *
 * Run: npx vitest run src/app/reports/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({
  reports: {} as Record<string, unknown>,
  toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
}))

vi.mock('@/hooks/useReports', () => ({ useAllReports: () => h.reports }))
vi.mock('@/hooks/useProjects', () => ({ useProjects: () => ({ data: [{ id: 'p1', name: 'Lab' }] }) }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))
vi.mock('@/components/ui', () => ({ useToast: () => h.toast, WikiInfoButton: () => null }))
vi.mock('@/components/shared/FeatureModelGate', () => ({ FeatureModelLine: () => null }))

import ReportsPage from './page'

const REPORT = { id: 'r1', projectId: 'p1', title: 'Pentest Report', filename: 'r.html', fileSize: 10,
  format: 'html', metrics: {}, hasNarratives: false, createdAt: '2026-10-01T00:00:00Z' }

beforeEach(() => {
  Object.values(h.toast).forEach(f => f.mockReset())
  h.reports = {
    reports: [REPORT], isLoading: false, error: null,
    generate: vi.fn(), isGenerating: false, generateError: null,
    deleteReport: vi.fn(), deleteReportAsync: vi.fn().mockResolvedValue(undefined), isDeleting: false,
  }
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function confirmDelete() {
  fireEvent.click(screen.getByTitle('Delete report'))
  fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
}

describe('reports page failures', () => {
  test('a failed list is shown with its cause, not as "No reports generated yet"', () => {
    h.reports = { ...h.reports, reports: [],
      error: new ApiError({ reason: 'Failed to list reports', status: 500, code: 'P1001' }) }
    render(<ReportsPage />)
    expect(screen.getByRole('alert')).toHaveTextContent('Failed to load reports: Failed to list reports (P1001 · HTTP 500)')
    expect(screen.queryByText('No reports generated yet')).toBeNull()
  })

  test('a refused delete is an error toast with the cause, never "Report deleted"', async () => {
    h.reports = { ...h.reports, deleteReportAsync: vi.fn().mockRejectedValue(
      new ApiError({ reason: 'Delete failed', status: 500, code: 'EACCES' })) }
    render(<ReportsPage />)
    confirmDelete()
    await waitFor(() => expect(h.toast.error).toHaveBeenCalledWith('Delete failed (EACCES · HTTP 500)'))
    expect(h.toast.success).not.toHaveBeenCalled()
  })

  test('a download 404 shows the route text and its status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Report file not found on disk' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } })))
    render(<ReportsPage />)
    fireEvent.click(screen.getByTitle('Download report'))
    await waitFor(() => expect(h.toast.error).toHaveBeenCalledWith('Report file not found on disk (HTTP 404)'))
  })

  test('a report made without narratives warns and says why', async () => {
    h.reports = { ...h.reports, generate: vi.fn().mockResolvedValue({ ...REPORT, narrativesSkipped: 'agent_unreachable' }) }
    render(<ReportsPage />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } })
    fireEvent.click(screen.getByRole('button', { name: /Generate Report/ }))
    await waitFor(() => expect(h.toast.warning).toHaveBeenCalledWith(
      'Report generated without AI narratives: the agent could not be reached (agent_unreachable).'))
    expect(h.toast.info).not.toHaveBeenCalled()
  })

  test.each([
    ['model_call_failed · RateLimitError · provider HTTP 429', 'the model call failed'],
    ['unreadable_answer', "the model's answer could not be read"],
  ])('a report without narratives because of %s names that reason', async (code, reason) => {
    h.reports = { ...h.reports, generate: vi.fn().mockResolvedValue({ ...REPORT, narrativesSkipped: code }) }
    render(<ReportsPage />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } })
    fireEvent.click(screen.getByRole('button', { name: /Generate Report/ }))
    await waitFor(() => expect(h.toast.warning).toHaveBeenCalledWith(
      `Report generated without AI narratives: ${reason} (${code}).`))
  })

  test('a failed generate toasts the cause', async () => {
    h.reports = { ...h.reports, generate: vi.fn().mockRejectedValue(
      new ApiError({ reason: 'Report generation failed', status: 504, code: 'non_json_response' })) }
    render(<ReportsPage />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'p1' } })
    fireEvent.click(screen.getByRole('button', { name: /Generate Report/ }))
    await waitFor(() => expect(h.toast.error).toHaveBeenCalledWith('Report generation failed (non_json_response · HTTP 504)'))
  })
})
