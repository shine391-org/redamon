/**
 * IP attribution across the project-form / workflow-graph layer (plan 11.5).
 *
 * The recon side dispatches `IpAttribution` (recon/partial_recon.py) and the
 * registry names IpAttributionSection; this pins the webapp half: the
 * workflow node, the play button, and node maps that only name real labels.
 *
 * Mirrors tlsxWiring.test.ts.
 */
import { describe, test, expect } from 'vitest'
import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from './nodeMapping'
import { WORKFLOW_TOOLS } from './WorkflowView/workflowDefinition'
import { INPUT_LOGIC_TOOLTIPS } from './WorkflowView/inputLogicTooltips'
import { PARTIAL_RECON_SUPPORTED_TOOLS } from '@/lib/recon-types'

describe('WORKFLOW_TOOLS -- IpAttribution entry', () => {
  const tool = WORKFLOW_TOOLS.find(t => t.id === 'IpAttribution')

  test('is registered against the Prisma column', () => {
    expect(tool).toBeDefined()
    expect(tool!.enabledField).toBe('ipAttributionEnabled')
  })

  test('sits with the HTTP probe, whose CDN flags and ASN it reads', () => {
    const httpx = WORKFLOW_TOOLS.find(t => t.id === 'Httpx')
    expect(tool!.group).toBe(httpx!.group)
  })

  test('is badged both: passive signals plus one TLS handshake', () => {
    expect(tool!.badge).toBe('both')
  })
})

describe('partial recon registration', () => {
  test('IpAttribution renders a play button', () => {
    expect(PARTIAL_RECON_SUPPORTED_TOOLS.has('IpAttribution')).toBe(true)
  })

  test('it has an input/output tooltip', () => {
    expect(INPUT_LOGIC_TOOLTIPS.IpAttribution).toBeDefined()
  })
})

describe('node maps', () => {
  test('reads IPs, their ports and the names resolving to them', () => {
    expect(SECTION_INPUT_MAP.IpAttribution).toEqual(['IP', 'Port', 'Subdomain'])
  })

  test('creates no node and enriches the IP', () => {
    expect(SECTION_NODE_MAP.IpAttribution).toEqual([])
    expect(SECTION_ENRICH_MAP.IpAttribution).toEqual(['IP'])
  })
})
