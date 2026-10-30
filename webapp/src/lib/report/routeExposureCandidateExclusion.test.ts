import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import { agentCandidateConfirmedOrNA } from '@/lib/graphMute'

/**
 * route_exposure writes pending leads (needs_agent_confirmation) and
 * signature findings under one source. The deliverable surfaces (report,
 * Insights, the triage reportable and disposition queries) must hide a pending
 * lead and keep the findings; the report must label the source.
 */

const ROOT = join(__dirname, '../../..')
const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf8')

describe('route_exposure pending exclusion on deliverable surfaces', () => {
  test('the predicate covers route_exposure', () => {
    expect(agentCandidateConfirmedOrNA('v')).toContain("'route_exposure'")
  })

  test.each([
    'src/lib/report/reportData.ts',
    'src/app/api/analytics/vulnerabilities/route.ts',
    'src/lib/triage/reportable.ts',
    'src/lib/triage/disposition.ts',
  ])('%s still applies the shared predicate', (file) => {
    expect(read(file)).toMatch(/agentCandidateConfirmedOrNA\('(v|n)'\)/)
  })

  test('the report labels route_exposure before the DAST branch', () => {
    const report = read('src/lib/report/reportData.ts')
    const label = report.indexOf("WHEN v.source = 'route_exposure' THEN 'Route Exposure'")
    expect(label).toBeGreaterThan(-1)
    expect(label).toBeLessThan(report.indexOf("WHEN ep IS NOT NULL THEN 'DAST'"))
  })

  test('the live graph test runs exactly the predicate the webapp renders', () => {
    const live = readFileSync(join(ROOT, '..', 'tests', 'test_route_exposure_graph_live.py'), 'utf8')
    const m = live.match(/EXCLUSION = \(([\s\S]*?)\)\n/)
    expect(m).not.toBeNull()
    const python = [...m![1].matchAll(/"([^"]*)"/g)].map(x => x[1]).join('')
    expect(python).toBe(agentCandidateConfirmedOrNA('v'))
  })
})
