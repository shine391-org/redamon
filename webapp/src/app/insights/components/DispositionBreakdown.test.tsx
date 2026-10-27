/**
 * Insights' disposition breakdown, beside the severity chart (plan 10.2).
 *
 * Run: npx vitest run src/app/insights/components/DispositionBreakdown.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup, within } from '@testing-library/react'
import { DispositionBreakdown } from './DispositionBreakdown'
import type { DispositionSummary } from '@/lib/triage/disposition'

afterEach(cleanup)

const summary = (over: Partial<DispositionSummary> = {}): DispositionSummary => ({
  reportable: 12, candidate: 340, info: 900, excluded: 4,
  blockers: [
    { blocker: 'not triaged yet', count: 200 },
    { blocker: 'credible, with impact worth planning for', count: 100 },
    { blocker: 'AI review: likely false positive', count: 20 },
    { blocker: 'no rule placed this higher', count: 10 },
    { blocker: 'KEV-listed, confidently detected and reachable', count: 6 },
    { blocker: 'likely real, likely exploited, real impact, reachable', count: 4 },
  ],
  ...over,
})

describe('DispositionBreakdown', () => {
  test('leads with reportable, candidates and info, in the shared labels', () => {
    render(<DispositionBreakdown data={summary()} isLoading={false} />)
    const tiles = within(screen.getByRole('list', { name: 'Findings by disposition' }))
      .getAllByRole('listitem').map((li) => li.textContent)
    expect(tiles).toEqual(['12Reportable', '340Candidate', '900Info'])
  })

  test('names the top five blockers with counts and sums the rest', () => {
    render(<DispositionBreakdown data={summary()} isLoading={false} />)
    const rows = within(screen.getByRole('list', { name: 'Candidates by blocker' }))
      .getAllByRole('listitem').map((li) => li.textContent)
    expect(rows).toEqual([
      'not triaged yet200',
      'credible, with impact worth planning for100',
      'AI review: likely false positive20',
      'no rule placed this higher10',
      'KEV-listed, confidently detected and reachable6',
      '1 other blocker4',
    ])
  })

  test('no candidates means no blocker list', () => {
    render(<DispositionBreakdown data={summary({ candidate: 0, blockers: [] })} isLoading={false} />)
    expect(screen.queryByRole('list', { name: 'Candidates by blocker' })).toBeNull()
  })

  test('counts that could not be read say so, and never show zeros', () => {
    render(<DispositionBreakdown data={null} isLoading={false} />)
    expect(screen.getByText(/could not be read/)).toBeTruthy()
    expect(screen.queryByText('0')).toBeNull()
  })

  test('a project with no findings is the card\'s empty state', () => {
    render(<DispositionBreakdown data={summary({ reportable: 0, candidate: 0, info: 0, excluded: 0, blockers: [] })} isLoading={false} />)
    expect(screen.getByText('No data available')).toBeTruthy()
  })

  test('while loading, the card shows its skeleton', () => {
    const { container } = render(<DispositionBreakdown data={undefined} isLoading />)
    expect(container.querySelector('.skeleton')).not.toBeNull()
  })
})
