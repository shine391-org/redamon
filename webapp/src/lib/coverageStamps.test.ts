import { describe, expect, test } from 'vitest'
import {
  COVERAGE_MODULES,
  COVERAGE_STAMP_PROPERTIES,
  coverageLines,
  recordedCoverageModules,
} from './coverageStamps'

const ALL: ReadonlySet<string> = new Set(COVERAGE_MODULES.map(m => m.key))
const NONE: ReadonlySet<string> = new Set<string>()

function line(props: Record<string, unknown>, recorded = ALL, module = 'js_recon') {
  return coverageLines(props, recorded).find(l => l.module === module)!
}

describe('coverageLines', () => {
  test('a complete stamp reads its counts', () => {
    const l = line({ js_recon_status: 'complete', js_recon_inputs: 12, js_recon_outputs: 0 })
    expect(l.state).toBe('complete')
    expect(l.text).toBe('complete, 12 files, 0 findings')
  })

  test('a partial stamp names its reason, and counts are singular when one', () => {
    const l = line({ js_recon_status: 'partial', js_recon_inputs: 1, js_recon_outputs: 1, js_recon_reason: 'file cap' })
    expect(l.state).toBe('partial')
    expect(l.text).toBe('partial (file cap), 1 file, 1 finding')
  })

  test('a failed stamp names its reason', () => {
    const l = line({ nuclei_status: 'failed', nuclei_inputs: 0, nuclei_outputs: 0, nuclei_reason: 'Docker not found' },
      ALL, 'nuclei')
    expect(l.text).toBe('failed (Docker not found)')
  })

  test('no input says what was missing', () => {
    expect(line({ js_recon_status: 'no_input', js_recon_inputs: 0 }).text).toBe('no input: the host served no JavaScript')
  })

  test('Nuclei counts URLs, not files', () => {
    expect(line({ nuclei_status: 'complete', nuclei_inputs: 3, nuclei_outputs: 2 }, ALL, 'nuclei').text)
      .toBe('complete, 3 URLs, 2 findings')
  })

  test('no stamp where the project has others is "not scanned"', () => {
    const l = line({})
    expect(l.state).toBe('not_scanned')
    expect(l.text).toBe('not scanned by this module')
  })

  test('no stamp anywhere in the project is "coverage not recorded", never "not scanned"', () => {
    const l = line({}, NONE)
    expect(l.state).toBe('not_recorded')
    expect(l.text).toBe('coverage not recorded')
  })

  test('the stamp time is formatted the way the drawer formats every graph timestamp', () => {
    const at = { year: 2026, month: 10, day: 25, hour: 8, minute: 0, second: 0 }
    expect(line({ js_recon_status: 'complete', js_recon_inputs: 1, js_recon_outputs: 0, js_recon_at: at }).at)
      .toBe('2026-10-25 08:00:00')
  })

  test('one line per module, in the declared order', () => {
    expect(coverageLines({}, ALL).map(l => l.module)).toEqual(['js_recon', 'nuclei'])
  })
})

describe('recordedCoverageModules', () => {
  test('a module is recorded when any BaseURL carries its status', () => {
    const nodes = [
      { type: 'BaseURL', properties: { nuclei_status: 'complete' } },
      { type: 'Endpoint', properties: { js_recon_status: 'complete' } },
      { type: 'BaseURL', properties: {} },
    ]
    expect([...recordedCoverageModules(nodes)]).toEqual(['nuclei'])
  })

  test('no graph to read means nothing is known to be recorded', () => {
    expect(recordedCoverageModules(undefined).size).toBe(0)
  })
})

test('the stamp properties are every module times every field', () => {
  expect(COVERAGE_STAMP_PROPERTIES).toEqual([
    'js_recon_at', 'js_recon_status', 'js_recon_inputs', 'js_recon_outputs', 'js_recon_reason',
    'nuclei_at', 'nuclei_status', 'nuclei_inputs', 'nuclei_outputs', 'nuclei_reason',
  ])
})
