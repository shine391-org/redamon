/**
 * The plugin group the gear menu gains (design §6.7, OQ-15, X27): after "Agent Skills", a
 * divider, then one labelled group per plugin with its items. The label is the plugin's name
 * with the plugin badge (never "Plugins": the same menu already names "MCP Tool Plugins").
 * Items are disabled until the first message makes a conversation, and a click runs the
 * injected handler with the session context.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))

const h = vi.hoisted(() => ({ contributions: [] as unknown[] | undefined, error: null as Error | null, refetch: (() => {}) as () => void }))
vi.mock('@/hooks/usePluginContributions', () => ({
  usePluginContributions: () => ({ data: h.contributions, error: h.error, refetch: h.refetch }),
}))

import { PhaseIndicatorBar } from './PhaseIndicatorBar'

type Props = React.ComponentProps<typeof PhaseIndicatorBar>

const skiller = {
  pluginId: 'skiller',
  displayName: 'Skiller',
  updating: false,
  chatSessionActions: [
    { key: 'analyze', label: 'Improve skill from this session', icon: 'sparkles', action: 'analyze', llm: true, async: true },
    { key: 'skill.text.versions', label: 'Skill versions', icon: 'history', coreScreen: 'skill.text.versions', llm: false, async: false },
  ],
  projectSkillsRow: [],
}

function draw(over: Partial<Props> = {}) {
  const props: Props = {
    currentPhase: 'informational',
    toolPhaseMap: {},
    attackPathType: 'ssrf',
    skillData: null,
    iterationCount: 0,
    stealthMode: false,
    settingsDropdownRef: { current: null },
    showSettingsDropdown: true,
    setShowSettingsDropdown: vi.fn(),
    setSettingsModal: vi.fn(),
    setShowModelModal: vi.fn(),
    projectId: 'p1',
    sessionId: 's1',
    conversationId: 'c1',
    onRunPluginAction: vi.fn(),
    ...over,
  }
  render(<PhaseIndicatorBar {...props} />)
  return props
}

beforeEach(() => {
  h.contributions = []
  h.error = null
  h.refetch = vi.fn()
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ servers: [] }), { status: 200 })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('plugin items that could not be loaded', () => {
  // They must not just vanish: a quiet line names the failure, and Retry asks again.
  test('a hint with the code and status, and Retry', async () => {
    const { ApiError } = await import('@/lib/apiError')
    h.contributions = undefined
    h.error = new ApiError({ reason: 'Plugin items could not be loaded', status: 500, code: 'P2024' })
    draw()
    expect(screen.getByTestId('plugin-items-error').textContent).toContain('Plugin items could not be loaded (P2024 · HTTP 500)')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(h.refetch).toHaveBeenCalled()
  })

  test('items already loaded stay shown when a later read fails', () => {
    h.contributions = [skiller]
    h.error = new Error('later failure')
    draw()
    expect(screen.queryByTestId('plugin-items-error')).toBeNull()
    expect(screen.getByRole('button', { name: /improve skill from this session/i })).toBeInTheDocument()
  })
})

describe('the plugin group', () => {
  test('no contributions: the menu still ends at Agent Skills, no divider', () => {
    draw()
    const items = Array.from(screen.getByText('Agent Behaviour').parentElement!.children).map((el) => el.textContent)
    expect(items).toEqual(['Agent Behaviour', 'Tool Matrix', 'Agent Skills'])
    expect(screen.queryByText('Skiller')).toBeNull()
  })

  test('with contributions: the three core items stay, then a group labelled by the plugin with its items', () => {
    h.contributions = [skiller]
    draw()
    expect(screen.getByText('Agent Behaviour')).toBeInTheDocument()
    // The group label is the plugin name with the plugin badge, not the bare word "Plugins".
    const label = screen.getByTitle('RedAmon plugin')
    expect(label.textContent).toContain('Skiller')
    expect(screen.getByRole('button', { name: /improve skill from this session/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /skill versions/i })).toBeInTheDocument()
  })

  test('each plugin item is a flex row so its icon sits beside the label, not above it', () => {
    h.contributions = [skiller]
    draw()
    for (const name of [/improve skill from this session/i, /skill versions/i]) {
      const item = screen.getByRole('button', { name })
      expect(item.className).toContain('pluginItem')
      expect(item.querySelector('svg')).not.toBeNull()
    }
  })

  test('items are disabled with "Send a message first" until there is a conversation', () => {
    h.contributions = [skiller]
    const p = draw({ conversationId: null })
    const item = screen.getByRole('button', { name: /improve skill from this session/i })
    expect(item).toBeDisabled()
    expect(item.getAttribute('title')).toMatch(/send a message first/i)
    fireEvent.click(item)
    expect(p.onRunPluginAction).not.toHaveBeenCalled()
  })

  test('clicking an item runs the handler with the plugin, the item and the session context', () => {
    h.contributions = [skiller]
    const p = draw()
    fireEvent.click(screen.getByRole('button', { name: /improve skill from this session/i }))
    expect(p.onRunPluginAction).toHaveBeenCalledWith(
      { pluginId: 'skiller', displayName: 'Skiller' },
      expect.objectContaining({ key: 'analyze', action: 'analyze' }),
      { projectId: 'p1', sessionId: 's1' },
    )
  })

  test('a coreScreen item runs the same handler (the flow routes it to the core screen)', () => {
    h.contributions = [skiller]
    const p = draw()
    fireEvent.click(screen.getByRole('button', { name: /skill versions/i }))
    expect(p.onRunPluginAction).toHaveBeenCalledWith(
      expect.objectContaining({ pluginId: 'skiller' }),
      expect.objectContaining({ coreScreen: 'skill.text.versions' }),
      { projectId: 'p1', sessionId: 's1' },
    )
  })

  test('an updating plugin is marked updating in its group', () => {
    h.contributions = [{ ...skiller, updating: true }]
    draw()
    expect(screen.getByText(/updating/i)).toBeInTheDocument()
  })

  test('a plugin with only a nav contribution adds no gear-menu group', () => {
    h.contributions = [{ pluginId: 'echo', displayName: 'Echo', updating: false, nav: { label: 'E', icon: 'puzzle', screen: 'ui/h.json' }, chatSessionActions: [], projectSkillsRow: [] }]
    draw()
    expect(screen.queryByText('Echo')).toBeNull()
    const items = Array.from(screen.getByText('Agent Behaviour').parentElement!.children).map((el) => el.textContent)
    expect(items).toEqual(['Agent Behaviour', 'Tool Matrix', 'Agent Skills'])
  })

  test('the menu closes after an item runs', () => {
    h.contributions = [skiller]
    const p = draw()
    fireEvent.click(screen.getByRole('button', { name: /skill versions/i }))
    expect(p.setShowSettingsDropdown).toHaveBeenCalledWith(false)
  })
})
