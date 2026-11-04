/**
 * The logs drawer is where a running scan is watched, so it must say when what
 * it shows is no longer live: the log stream was lost or refused, or the status
 * could not be read (the badge then shows the last known state).
 *
 * Run: npx vitest run src/app/graph/components/ReconLogsDrawer/ReconLogsDrawer.errors.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ReconLogsDrawer } from './ReconLogsDrawer'
import type { ReconStatus } from '@/lib/recon-types'

afterEach(cleanup)

function renderDrawer(status: ReconStatus, extra: Record<string, unknown> = {}) {
  return render(
    <ReconLogsDrawer isOpen onClose={() => {}} logs={[]} currentPhase={null} currentPhaseNumber={null}
      status={status} onClearLogs={() => {}} title="GVM Vulnerability Scan Logs" {...extra} />,
  )
}

describe('ReconLogsDrawer notices', () => {
  test('a lost stream on a live run is shown with its cause', () => {
    renderDrawer('running', { streamError: 'Failed to connect to GVM log stream (orchestrator_unreachable · HTTP 503)' })
    expect(screen.getByRole('alert').textContent)
      .toBe('Log stream: Failed to connect to GVM log stream (orchestrator_unreachable · HTTP 503)')
  })

  test('a finished run closed its stream on purpose: no notice', () => {
    renderDrawer('completed', { streamError: 'Connection lost. Max reconnection attempts reached.' })
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('a failed status read is shown as is, next to the last known status', () => {
    renderDrawer('running', { statusError: 'GVM status unavailable (orchestrator_timeout · HTTP 504)' })
    expect(screen.getByRole('alert').textContent).toBe('GVM status unavailable (orchestrator_timeout · HTTP 504)')
    expect(screen.getByText('Running...')).toBeTruthy()
  })

  test('both notices can show at once', () => {
    renderDrawer('paused', { statusError: 'a (HTTP 503)', streamError: 'b' })
    expect(screen.getAllByRole('alert').map(n => n.textContent)).toEqual(['a (HTTP 503)', 'Log stream: b'])
  })

  test('the run\'s own failure stays in the status line', () => {
    renderDrawer('error', { errorMessage: 'Container exited with code 137: killed (out of memory)' })
    expect(screen.getByText('Error: Container exited with code 137: killed (out of memory)')).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
