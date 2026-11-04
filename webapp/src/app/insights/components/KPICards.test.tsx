/**
 * Insights KPI row: a pipeline or the agent the dashboard could not reach must
 * read as "unavailable", never as "idle" or 0 (a running scan looked finished).
 *
 * Run: npx vitest run src/app/insights/components/KPICards.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { KPICards } from './KPICards'
import type { PipelineStatusData } from '../types'

afterEach(cleanup)

describe('KPICards pipeline cards', () => {
  test('an unreachable pipeline says status unavailable with its code, the others keep their state', () => {
    const pipeline: PipelineStatusData = {
      recon: { status: 'running', currentPhase: 'Port scan' },
      gvm: { reachable: false, code: 'orchestrator_unreachable' },
      githubHunt: { reachable: false, code: 'orchestrator_error', upstreamStatus: 500 },
    }
    render(<KPICards items={[]} pipeline={pipeline} />)
    expect(screen.getByText('running')).toBeTruthy()
    expect(screen.getByText('status unavailable (orchestrator_unreachable)')).toBeTruthy()
    expect(screen.getByText('status unavailable (orchestrator_error · upstream HTTP 500)')).toBeTruthy()
    expect(screen.queryByText('idle')).toBeNull()
  })

  test('a failed pipeline-status request marks every pipeline unavailable, with the reason on hover', () => {
    render(<KPICards items={[]} pipelineError="Failed to load pipeline status (internal_error · HTTP 500)" />)
    const cells = screen.getAllByText('status unavailable')
    expect(cells).toHaveLength(3)
    expect(cells[0].parentElement?.getAttribute('title')).toBe('Failed to load pipeline status (internal_error · HTTP 500)')
    expect(screen.queryByText('idle')).toBeNull()
  })

  test('a null pipeline with no error is still idle', () => {
    render(<KPICards items={[]} pipeline={{ recon: null, gvm: null, githubHunt: null }} />)
    expect(screen.getAllByText('idle')).toHaveLength(3)
  })
})

describe('KPICards active shells', () => {
  test('a failed sessions request reads unavailable, not 0', () => {
    render(<KPICards items={[]} sessionsError="Failed to load agent sessions (agent_unreachable · HTTP 503)" />)
    const value = screen.getByText('unavailable')
    expect(value.closest('.statCard')?.getAttribute('title')).toBe('Failed to load agent sessions (agent_unreachable · HTTP 503)')
    expect(screen.queryByText('0')).toBeNull()
  })

  test('no sessions and no error is 0', () => {
    render(<KPICards items={[]} sessions={{ sessions: [], jobs: [], non_msf_sessions: [] } as never} />)
    expect(screen.getByText('0')).toBeTruthy()
  })
})
