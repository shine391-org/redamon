import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ExpandedRowDetail } from './ExpandedRowDetail'
import type { TableRow } from '../../hooks/useTableData'

afterEach(cleanup)

function row(type: string, properties: Record<string, unknown>, connectionsIn: TableRow['connectionsIn'] = []): TableRow {
  return {
    node: { id: '7', type, name: 'n', properties },
    connectionsIn, connectionsOut: [], getLevel2: () => [], getLevel3: () => [],
  }
}

const lead = { source: 'route_exposure', exposure_kind: 'sensitive_data', needs_agent_confirmation: true,
  leak_signals: ['secret'], anon_status: 200, authed_status: 200 }

describe('ExpandedRowDetail route exposure block', () => {
  it('labels a lead and takes its confirmation from the row\'s own CONFIRMS edge', () => {
    render(<ExpandedRowDetail row={row('Vulnerability', lead)} />)
    const block = screen.getByTestId('route-exposure-detail')
    expect(block).toHaveTextContent('Sensitive data in the answer')
    expect(block).toHaveTextContent('a secret')
    expect(block).toHaveTextContent('anonymous 200 · logged in 200')
    expect(block).toHaveTextContent('waiting for the agent')
    cleanup()

    render(<ExpandedRowDetail row={row('Vulnerability', lead,
      [{ nodeId: '9', nodeName: 'proof', nodeType: 'ChainFinding', relationType: 'CONFIRMS' }])} />)
    expect(screen.getByTestId('route-exposure-detail')).toHaveTextContent('Confirmed by the agent')
  })

  it('keeps the raw properties beside it, after the summary', () => {
    render(<ExpandedRowDetail row={row('Vulnerability', lead)} />)
    expect(screen.getByText('leak_signals')).toBeInTheDocument()
    // A wide table stretches the row past the viewport: the summary must lead.
    const sections = [...screen.getByTestId('route-exposure-detail').parentElement!.children]
    expect(sections[0]).toBe(screen.getByTestId('route-exposure-detail'))
    expect(sections[1]).toHaveTextContent(/^Properties/)
  })

  it('a finding from another source has no block', () => {
    render(<ExpandedRowDetail row={row('Vulnerability', { source: 'nuclei', anon_status: 200 })} />)
    expect(screen.queryByTestId('route-exposure-detail')).toBeNull()
  })
})
