import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join, relative } from 'path'

/**
 * Every finding the client report or Insights counts or lists carries the
 * board's verdict: `reportCountable` beside `notMuted`.
 *
 * Each of these files hand-writes its own Cypher, so each query is a separate
 * enforcement site, and one that forgets the predicate prints a finding a
 * person judged false as a live Critical. The behaviour itself is proven on a
 * real graph in reportData.integration.test.ts; this guards that no site is
 * missed, including ones added later.
 */

const FINDING_LABELS = [
  'Vulnerability', 'JsReconFinding', 'Secret', 'MultiscannerFinding',
  'GithubSecret', 'GithubSensitiveFile', 'MalPackageFinding', 'ExploitGvm',
]

const REPORT = join(__dirname, 'reportData.ts')
const ANALYTICS_DIR = join(__dirname, '../../app/api/analytics')

function routeFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) return routeFiles(p)
    return name === 'route.ts' ? [p] : []
  })
}

/** `[file, variable, query]` for each finding variable a query mute-filters. */
function findingSites(file: string): [string, string, string][] {
  // Comments may quote backticks, which would pair the wrong literals.
  const src = readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '')
  const sites: [string, string, string][] = []
  for (const m of src.matchAll(/`([^`]*)`/g)) {
    const q = m[1]
    for (const v of q.matchAll(/\$\{notMuted\('(\w+)'\)\}/g)) {
      const name = v[1]
      const bound = new RegExp(`\\(${name}:(${FINDING_LABELS.join('|')})\\b`)
      if (bound.test(q)) sites.push([relative(join(__dirname, '../..'), file), name, q])
    }
  }
  return sites
}

describe('the board verdict on deliverable surfaces', () => {
  const files = [REPORT, ...routeFiles(ANALYTICS_DIR)]
  const sites = files.flatMap(findingSites)

  test('the sweep finds the finding queries it is meant to guard', () => {
    // A regex that silently matched nothing would make the next test vacuous.
    expect(sites.length).toBeGreaterThan(40)
    expect(sites.some(([f]) => f.endsWith('reportData.ts'))).toBe(true)
    expect(sites.some(([f]) => f.includes('analytics/vulnerabilities'))).toBe(true)
    expect(sites.some(([f]) => f.includes('redzone/secrets'))).toBe(true)
  })

  test('every mute-filtered finding query also applies reportCountable to the same variable', () => {
    const offenders = sites
      .filter(([, v, q]) => !q.includes(`\${reportCountable('${v}')}`))
      // The risk gauge's input keeps open findings only, which is stricter.
      .filter(([, v, q]) => !q.includes(`coalesce(${v}.triage_state, 'open') = 'open'`))
      .map(([f, v, q]) => `${f} (${v}): ${q.trim().split('\n')[0]}`)
    expect(offenders).toEqual([])
  })

  test('the risk gauge input is left as it is: it ranks, it does not count', () => {
    const src = readFileSync(REPORT, 'utf8')
    expect(src).toContain("AND coalesce(n.triage_state, 'open') = 'open'")
    expect(src).toContain("AND coalesce(n.triage_status, '') <> 'likely_noise'")
  })
})
