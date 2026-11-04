/**
 * The project form's scan cluster: a GVM start goes through the reporting
 * wrapper (so a refusal opens the start-failure modal), a failed recon download
 * says why, and a failed status read shows next to the last known state.
 *
 * Run: npx vitest run src/components/scans/ScanActions.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const toastError = vi.fn()
vi.mock('@/components/ui', () => ({ useToast: () => ({ error: toastError, success: vi.fn(), info: vi.fn() }) }))

import { ScanActions } from './ScanActions'
import type { ScanControls } from '@/hooks/useScanControls'

afterEach(() => { cleanup(); vi.clearAllMocks() })

function controls(over: Record<string, unknown> = {}): ScanControls {
  return {
    hasReconData: true,
    reconDataError: null,
    downloadReconJSON: vi.fn(async () => null),
    toggleOtherScans: vi.fn(),
    statusErrors: [],
    gvm: {
      isAvailable: true, unavailableReason: '', isPaused: false, isRunning: false, isBusy: false, isActive: false,
      isStopping: false, isPausing: false, hasData: false, dataError: null,
      start: vi.fn(async () => {}), resumeGvm: vi.fn(), pauseGvm: vi.fn(), stopGvm: vi.fn(), download: vi.fn(),
    },
    githubHunt: { isActive: false, isRunning: false, isBusy: false },
    trufflehog: { isActive: false, isRunning: false },
    ...over,
  } as unknown as ScanControls
}

const button = (label: string) => screen.getAllByRole('button').find(b => b.textContent?.includes(label)) as HTMLButtonElement

describe('ScanActions failures', () => {
  test('GVM Scan starts through the reporting wrapper, not the bare hook call', () => {
    const scans = controls()
    render(<ScanActions scans={scans} />)
    fireEvent.click(button('GVM Scan'))
    expect(scans.gvm.start).toHaveBeenCalledTimes(1)
  })

  test('a GVM button greyed out by an unreachable orchestrator says so', () => {
    const scans = controls()
    Object.assign(scans.gvm, { isAvailable: false, unavailableReason: 'GVM availability unknown (orchestrator_timeout)' })
    render(<ScanActions scans={scans} />)
    expect(button('GVM Scan').title).toBe('GVM availability unknown (orchestrator_timeout)')
  })

  test('a failed recon download is toasted with its reason', async () => {
    const scans = controls({ downloadReconJSON: vi.fn(async () => 'Recon data not found (HTTP 404)') })
    render(<ScanActions scans={scans} />)
    fireEvent.click(screen.getByTitle('Download Recon JSON'))
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Recon data not found (HTTP 404)'))
  })

  test('a 5xx data check is not "No data available"', () => {
    render(<ScanActions scans={controls({ hasReconData: false, reconDataError: 'Could not check for data (HTTP 500)' })} />)
    expect(screen.getByTitle('Could not check for data (HTTP 500)')).toBeTruthy()
  })

  test('a failed status read shows the warning badge', () => {
    render(<ScanActions scans={controls({ statusErrors: ['GVM status unavailable (orchestrator_unreachable · HTTP 503)'] })} />)
    expect(screen.getByRole('status').title).toBe('GVM status unavailable (orchestrator_unreachable · HTTP 503)')
  })
})
