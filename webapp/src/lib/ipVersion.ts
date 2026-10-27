/**
 * Every spelling of `IP.version` a graph may hold. Writers store 'ipv4' /
 * 'ipv6'; the IP-mode writer stored 'v4' / 'v6', and graphs written before it
 * was fixed, or scan versions restored from them, still carry that.
 */
const SPELLINGS = { ipv4: ['ipv4', 'v4'], ipv6: ['ipv6', 'v6'] } as const

/** Cypher, true when `alias` is an IP node of that version, in either spelling. */
export function ipVersionIs(alias: string, version: keyof typeof SPELLINGS): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) throw new Error(`not a Cypher variable: ${alias}`)
  return `${alias}.version IN [${SPELLINGS[version].map(v => `'${v}'`).join(', ')}]`
}
