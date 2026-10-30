/**
 * Insights failure banner: names each failed query with its code and status, so a
 * Neo4j outage no longer reads like an empty project.
 *
 * Run: npx vitest run src/app/insights/components/QueryErrors.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { QueryErrors } from './QueryErrors'
import { ApiError } from '@/lib/apiError'

afterEach(cleanup)

describe('QueryErrors', () => {
  test('lists every failed query with its reason, code and status', () => {
    render(<QueryErrors queries={[
      { label: 'Graph overview', isError: true, error: new ApiError({ reason: 'Query failed', status: 500, code: 'Neo.TransientError.General.DatabaseUnavailable' }) },
      { label: 'Vulnerabilities', isError: false, error: null },
      { label: 'Activity', isError: true, error: new ApiError({ reason: 'Failed to load activity', status: 0, code: 'network_error' }) },
    ]} />)
    expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.getByText('Graph overview: Query failed (Neo.TransientError.General.DatabaseUnavailable · HTTP 500)')).toBeTruthy()
    expect(screen.getByText('Activity: Failed to load activity (network_error)')).toBeTruthy()
    expect(screen.queryByText(/Vulnerabilities/)).toBeNull()
  })

  test('renders nothing when every query succeeded (an empty project stays empty, not failed)', () => {
    const { container } = render(<QueryErrors queries={[{ label: 'Graph overview', isError: false, error: null }]} />)
    expect(container.innerHTML).toBe('')
  })
})
