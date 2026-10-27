/**
 * ipVersionIs: the Cypher every IPv4 / IPv6 count uses, over both spellings
 * IP.version has been written with.
 *
 * Run: npx vitest run src/lib/ipVersion.test.ts
 */
import { describe, test, expect } from 'vitest'
import { ipVersionIs } from './ipVersion'

describe('ipVersionIs', () => {
  test('matches the current and the IP-mode spelling', () => {
    expect(ipVersionIs('ip', 'ipv4')).toBe("ip.version IN ['ipv4', 'v4']")
    expect(ipVersionIs('i', 'ipv6')).toBe("i.version IN ['ipv6', 'v6']")
  })

  test('refuses anything but a Cypher variable, so nothing is spliced into a query', () => {
    expect(() => ipVersionIs('ip) OR true //', 'ipv4')).toThrow(/not a Cypher variable/)
    expect(() => ipVersionIs('', 'ipv4')).toThrow()
  })
})
