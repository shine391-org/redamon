/**
 * The graph toolbar's scan buttons keep their last known state when a status
 * read fails, so the toolbar must say the status is unavailable; and a GVM
 * button greyed out because the orchestrator did not answer must not claim
 * that GVM is not installed.
 *
 * Run: npx vitest run src/app/graph/components/GraphToolbar/GraphToolbar.errors.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { GraphToolbar } from './GraphToolbar'

afterEach(cleanup)

const base = {
  projectId: 'p1', is3D: false, showLabels: true, onToggle3D: () => {}, onToggleLabels: () => {},
  onStartRecon: () => {}, hasReconData: true,
}

function gvmButton(): HTMLButtonElement {
  return screen.getAllByRole('button').find(b => b.textContent?.includes('GVM Scan')) as HTMLButtonElement
}

describe('GraphToolbar failure text', () => {
  test('GVM greyed out by an unreachable orchestrator says so', () => {
    render(<GraphToolbar {...base} gvmAvailable={false}
      gvmUnavailableReason="GVM availability unknown: the recon orchestrator did not report it (orchestrator_unreachable · ECONNREFUSED)" />)
    expect(gvmButton().disabled).toBe(true)
    expect(gvmButton().title).toMatch(/orchestrator_unreachable · ECONNREFUSED/)
    expect(gvmButton().title).not.toMatch(/not installed/)
  })

  test('without a reason the install hint is kept', () => {
    render(<GraphToolbar {...base} gvmAvailable={false} />)
    expect(gvmButton().title).toMatch(/^GVM is not installed/)
  })

  test('a failed status read shows a warning listing every cause', () => {
    render(<GraphToolbar {...base} gvmStatus="running" scanStatusErrors={[
      'GVM status unavailable (orchestrator_unreachable · HTTP 503)', null, undefined,
      'Supply-Chain status unavailable (orchestrator_timeout · HTTP 504)',
    ]} />)
    const warning = screen.getByRole('status')
    expect(warning.textContent).toBe('Status unavailable')
    expect(warning.title).toBe(
      'GVM status unavailable (orchestrator_unreachable · HTTP 503)\nSupply-Chain status unavailable (orchestrator_timeout · HTTP 504)')
  })

  test('no failed read, no warning', () => {
    render(<GraphToolbar {...base} scanStatusErrors={[null, null]} />)
    expect(screen.queryByRole('status')).toBeNull()
  })

  test('a 5xx on the data check is not "No data available"', () => {
    render(<GraphToolbar {...base} hasReconData={false} reconDataError="Could not check for data (HTTP 500)"
      hasGvmData={false} gvmDataError="Could not check for data (network_error)" />)
    const titles = screen.getAllByRole('button').map(b => b.title)
    expect(titles).toContain('Could not check for data (HTTP 500)')
    expect(titles).toContain('Could not check for data (network_error)')
  })
})
