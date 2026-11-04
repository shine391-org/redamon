import { describe, test, expect } from 'vitest'
import { notMuted, agentCandidateConfirmedOrNA, AGENT_CANDIDATE_SOURCES } from './graphMute'

describe('agentCandidateConfirmedOrNA (agent-candidate pending exclusion, §12-D)', () => {
  test('is scoped to the agent-candidate sources only', () => {
    const p = agentCandidateConfirmedOrNA('v')
    expect(p).toContain("v.source IN ['serialized_scan', 'route_exposure']")
    expect([...AGENT_CANDIDATE_SOURCES]).toEqual(['serialized_scan', 'route_exposure'])
  })

  test('gates on needs_agent_confirmation and the CONFIRMS edge', () => {
    const p = agentCandidateConfirmedOrNA('v')
    expect(p).toContain('needs_agent_confirmation')
    expect(p).toContain('(:ChainFinding)-[:CONFIRMS]->(v)')
  })

  test('is an exclusion (NOT ...), so other sources and confirmed candidates pass', () => {
    const p = agentCandidateConfirmedOrNA('v')
    expect(p.trimStart().startsWith('NOT (')).toBe(true)
  })

  test('binds the given variable', () => {
    expect(agentCandidateConfirmedOrNA('x')).toContain('x.source')
    expect(notMuted('x')).toContain('x.stale_since IS NULL')
  })
})
