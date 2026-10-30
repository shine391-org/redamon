/**
 * The drawer prompts for recon's route-exposure findings (plan §23.11) sit in
 * the existing skill groups, and every kind or class they name is one recon
 * writes: a prompt naming a value no node carries would query nothing.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/suggestionData.routeExposure.test.ts
 */
import { describe, test, expect } from 'vitest'
import { EXPLOITATION_GROUPS } from './suggestionData'

// recon/route_exposure/signatures.py KINDS, plus the two lead kinds.
const KINDS = new Set(['anonymous_access', 'sensitive_data', 'vcs_exposure', 'env_file', 'config_file', 'backup_file',
  'debug_console', 'debug_endpoint', 'debug_page', 'route_catalog', 'secret_in_response'])
// recon/route_exposure/verdict.py route_class
const CLASSES = new Set(['old_version', 'client_gated', 'debug_management', 'admin_function', 'data_export',
  'uploaded_content', 'internal_api', 'unknown'])

function prompts(groupId: string) {
  const group = EXPLOITATION_GROUPS.find(g => g.id === groupId)
  expect(group, groupId).toBeTruthy()
  return group!.items.flatMap(i => i.suggestions)
}

describe('route exposure drawer prompts', () => {
  test.each([
    ['access_control', 'Confirm the route exposure leads recon found'],
    ['access_control', 'Check whose data the exposed export returns'],
    ['path_traversal', 'Prove the exposed .git and .env files recon found'],
    // There is no rce group: the RCE prompts live in Web Application Attacks.
    ['web_attacks', 'Check the debug consoles recon found, without exploiting them'],
  ])('%s carries "%s"', (groupId, label) => {
    const found = prompts(groupId).find(s => s.label === label)
    expect(found).toBeTruthy()
    const text = found!.prompt
    expect(text).toMatch(/source route_exposure/)
    for (const kind of text.match(/\b[a-z]+(?:_[a-z]+)+\b/g) ?? []) {
      if (kind === 'route_exposure' || kind.startsWith('execute_') || ['needs_agent_confirmation', 'exposure_kind',
        'route_class', 'pii_types'].includes(kind)) continue
      expect(KINDS.has(kind) || CLASSES.has(kind), kind).toBe(true)
    }
    expect(text).toMatch(/exact finding id/)
  })
})
