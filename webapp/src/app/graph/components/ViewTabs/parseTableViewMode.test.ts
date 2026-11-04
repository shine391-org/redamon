/**
 * Deep-link table-mode parsing.
 *
 * `/graph?table=<mode>` is an untrusted, potentially stale query param. It used
 * to be cast straight to TableViewMode, so an unknown value matched no render
 * branch and silently fell through to All Nodes - the link looked like it
 * worked while showing the wrong table.
 *
 * Run: npx vitest run src/app/graph/components/ViewTabs/parseTableViewMode.test.ts
 */
import { describe, test, expect } from 'vitest'
import { parseTableViewMode } from './ViewTabs'

describe('parseTableViewMode', () => {
  test('accepts every current mode', () => {
    for (const mode of [
      'nodeDetails', 'all', 'jsRecon', 'aiSurface', 'aiRisk', 'killChain',
      'blastRadius', 'takeover', 'secrets', 'netInitAccess', 'graphql',
      'webInitAccess', 'paramMatrix', 'sharedInfra', 'dnsEmail', 'threatIntel',
      'jsDepSignals', 'supplyChainSca', 'dnsDrift', 'webCachePoison', 'routeExposure',
      'reconDelta', 'scanSchedule',
    ]) {
      expect(parseTableViewMode(mode)).toBe(mode)
    }
  })

  // The package/OSV feature took the "Supply-Chain" name, so the old table was
  // renamed. Bookmarks and external links pointing at the old slug must not
  // silently land on All Nodes.
  test('aliases the legacy supplyChain slug to jsDepSignals', () => {
    expect(parseTableViewMode('supplyChain')).toBe('jsDepSignals')
  })

  test('rejects unknown, empty and nullish values instead of casting them', () => {
    expect(parseTableViewMode('bogusMode')).toBeNull()
    expect(parseTableViewMode('')).toBeNull()
    expect(parseTableViewMode(null)).toBeNull()
    expect(parseTableViewMode(undefined)).toBeNull()
  })

  test('is case-sensitive (no accidental prototype hits)', () => {
    expect(parseTableViewMode('SupplyChainSca')).toBeNull()
    expect(parseTableViewMode('constructor')).toBeNull()
    expect(parseTableViewMode('toString')).toBeNull()
    expect(parseTableViewMode('__proto__')).toBeNull()
  })
})
