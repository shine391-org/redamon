/**
 * The agent's route-exposure switches in PathTraversalSection and RceSection
 * (plan §23.11): they show only while the recon module is on, each writes its
 * own field, off by default, and each names the RoE gate it still needs.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/RouteExposureSwitches.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { PathTraversalSection } from './PathTraversalSection'
import { RceSection } from './RceSection'

vi.mock('@/components/ui/WikiInfoButton', () => ({ WikiInfoButton: () => null }))
vi.mock('@/components/ui/Toggle/Toggle', () => ({
  Toggle: ({ checked, onChange, ...rest }: { checked: boolean; onChange: (v: boolean) => void }) => (
    <button role="switch" aria-checked={checked} aria-label={(rest as Record<string, string>)['aria-label']}
            onClick={() => onChange(!checked)} />
  ),
}))

afterEach(() => cleanup())

const SECTIONS = {
  PathTraversalSection: {
    Component: PathTraversalSection,
    switches: [
      ['Reconstruct exposed .git repositories', 'pathTraversalGitReconstructEnabled'],
      ['Validate secrets found in exposed files', 'pathTraversalValidateSecretsEnabled'],
    ],
  },
  RceSection: {
    Component: RceSection,
    switches: [['Analyse exposed heap dumps', 'rceHeapdumpAnalysisEnabled']],
  },
} as const

function renderSection(name: keyof typeof SECTIONS, data: Record<string, unknown>) {
  const { Component } = SECTIONS[name]
  const updateField = vi.fn()
  const view = render(<Component data={data as never} updateField={updateField as never} />)
  return { ...view, updateField }
}

describe.each(Object.keys(SECTIONS) as (keyof typeof SECTIONS)[])('%s', (name) => {
  test('with the module off the switches are replaced by one line', () => {
    renderSection(name, { routeExposureEnabled: false })
    for (const [label] of SECTIONS[name].switches) {
      expect(screen.queryByRole('switch', { name: label })).toBeNull()
    }
    expect(screen.getByText(/the Route Exposure scan finds\. Enable it in Vulnerability Scanning\./)).toBeTruthy()
  })

  test.each(SECTIONS[name].switches.map(([label, field]) => [label, field]))(
    '%s writes %s and is off by default', (label, field) => {
      // A project saved before the column existed has no value: the control reads off.
      const { updateField } = renderSection(name, { routeExposureEnabled: true })
      const toggle = screen.getByRole('switch', { name: label })
      expect(toggle.getAttribute('aria-checked')).toBe('false')
      fireEvent.click(toggle)
      expect(updateField).toHaveBeenCalledWith(field, true)
    })
})

test.each([
  ['PathTraversalSection', /Needs data exfiltration allowed in/],
  ['RceSection', /data exfiltration allowed and sensitive data handling above "no access" in/],
] as const)('%s names the RoE gate and links to the RoE tab', (name, caution) => {
  const onOpenRoe = vi.fn()
  const { Component } = SECTIONS[name]
  render(<Component data={{ routeExposureEnabled: true } as never} updateField={vi.fn() as never} onOpenRoe={onOpenRoe} />)
  expect(screen.getByText(caution)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Rules of Engagement' }))
  expect(onOpenRoe).toHaveBeenCalled()
  cleanup()
  // The chat SettingsModal has no tabs: the same words, no button.
  renderSection(name, { routeExposureEnabled: true })
  expect(screen.getByText(caution)).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Rules of Engagement' })).toBeNull()
})
