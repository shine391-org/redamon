/**
 * The Priority Board's disposition chip and the one-line disposition shown by
 * the detail panel and the node drawer (plan 10.2b).
 *
 * Run: npx vitest run src/app/graph/components/Triage/DispositionChip.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { DispositionChip, DispositionLine } from './DispositionChip'
import { BLOCKER_NOT_TRIAGED, DISPOSITION_MEANINGS } from '@/lib/triage/disposition'

afterEach(cleanup)

describe('DispositionChip', () => {
  test('a candidate shows its label, with the blocker as its tooltip', () => {
    render(<DispositionChip result={{ disposition: 'candidate', blocker: 'credible, with impact worth planning for' }} />)
    const chip = screen.getByText('Candidate').closest('[data-disposition]') as HTMLElement
    expect(chip.dataset.disposition).toBe('candidate')
    expect(chip.title).toBe('Candidate, blocked by credible, with impact worth planning for')
  })

  test('an untriaged candidate says so in its tooltip', () => {
    render(<DispositionChip result={{ disposition: 'candidate', blocker: BLOCKER_NOT_TRIAGED }} />)
    expect(screen.getByText('Candidate').closest('[data-disposition]')!.getAttribute('title'))
      .toBe('Candidate, not triaged yet')
  })

  test.each(['reportable', 'info', 'excluded'] as const)('%s explains itself in the tooltip', (d) => {
    const { container } = render(<DispositionChip result={{ disposition: d, blocker: null }} />)
    const chip = container.querySelector('[data-disposition]') as HTMLElement
    expect(chip.dataset.disposition).toBe(d)
    expect(chip.title).toContain(DISPOSITION_MEANINGS[d])
  })

  test('props it could not read render no chip, never a default Reportable', () => {
    const { container } = render(<DispositionChip result={null} />)
    expect(container.innerHTML).toBe('')
  })

  test('the icon alone still names the disposition, so the narrow chip loses nothing', () => {
    const { container } = render(<DispositionChip result={{ disposition: 'reportable', blocker: null }} />)
    const chip = container.querySelector('[data-disposition]') as HTMLElement
    expect(chip.getAttribute('aria-label')).toBe(chip.title)
    expect(chip.querySelector('svg')).not.toBeNull()
    expect(chip.querySelector('.dispositionText')!.textContent).toBe('Reportable')
  })

  test('at the board\'s 900 px breakpoint the label collapses and the icon stays', () => {
    const css = readFileSync(join(__dirname, 'DispositionChip.module.css'), 'utf8')
    const narrow = css.slice(css.indexOf('@media (max-width: 900px)'))
    expect(narrow).toMatch(/\.dispositionText\s*{[^}]*display:\s*none/)
    // The same breakpoint the board's toolbar already folds at.
    const board = readFileSync(join(__dirname, 'TriageTable.module.css'), 'utf8')
    expect(board).toContain('@media (max-width: 900px)')
  })
})

describe('DispositionLine', () => {
  test('one line, "Disposition: Candidate, blocked by <blocker>"', () => {
    render(<DispositionLine result={{ disposition: 'candidate', blocker: 'AI review: likely false positive' }} />)
    expect(screen.getByTestId('disposition-line').textContent)
      .toBe('Disposition: Candidate, blocked by AI review: likely false positive')
  })

  test('not triaged reads plainly', () => {
    render(<DispositionLine result={{ disposition: 'candidate', blocker: BLOCKER_NOT_TRIAGED }} />)
    expect(screen.getByTestId('disposition-line').textContent).toBe('Disposition: Candidate, not triaged yet')
  })

  test('nothing to read renders nothing', () => {
    const { container } = render(<DispositionLine result={null} />)
    expect(container.innerHTML).toBe('')
  })
})
