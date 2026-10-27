/**
 * Insights says what the Priority Board set aside, under the severity charts.
 *
 * Run: npx vitest run src/app/insights/components/JudgedFindingsNote.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { JudgedFindingsNote } from './JudgedFindingsNote'

afterEach(cleanup)

describe('JudgedFindingsNote', () => {
  test('one line per non-zero count, saying whether it is still counted', () => {
    render(<JudgedFindingsNote judged={{ personFalsePositive: 3, resolved: 1, aiFlagged: 2 }} />)
    const lines = screen.getAllByRole('listitem').map((li) => li.textContent)
    expect(lines).toEqual([
      '3 judged false positive by a person: not counted above',
      '1 resolved (fixed, gone, inactive): not counted above',
      '2 flagged as likely false positive by AI review: still counted above',
    ])
  })

  test('a zero count is not shown', () => {
    render(<JudgedFindingsNote judged={{ personFalsePositive: 0, resolved: 5, aiFlagged: 0 }} />)
    expect(screen.getAllByRole('listitem')).toHaveLength(1)
  })

  test('nothing renders when every count is zero', () => {
    const { container } = render(<JudgedFindingsNote judged={{ personFalsePositive: 0, resolved: 0, aiFlagged: 0 }} />)
    expect(container.innerHTML).toBe('')
  })

  test('counts that could not be read render nothing, never a 0', () => {
    for (const judged of [null, undefined]) {
      const { container } = render(<JudgedFindingsNote judged={judged} />)
      expect(container.innerHTML).toBe('')
      cleanup()
    }
  })
})
