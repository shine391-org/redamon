/**
 * RoE excluded-host matching with the semantics of recon/helpers/roe_scope.py
 * (`_is_roe_excluded`, `_normalize_host`, `_normalize_scope_entry`), the matcher
 * the scans enforce. A copy, because the webapp cannot import Python; both sides
 * run recon/tests/fixtures/roe_exclusion_vectors.json, so a rule changed on one
 * side only fails a test.
 *
 * Browser-safe (no node:net): the project form runs it too.
 */

type Ip = { version: 4 | 6; value: bigint }

const IPV4_BITS = 32
const IPV6_BITS = 128

/** Python's `ipaddress` IPv4 parser: four decimal octets, no leading zeros. */
function parseIpv4(text: string): bigint | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  let value = 0n
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    if (part.length > 1 && part.startsWith('0')) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = (value << 8n) | BigInt(octet)
  }
  return value
}

/** Python's `ipaddress` IPv6 parser: one `::` at most, an embedded IPv4 tail, a `%zone`. */
function parseIpv6(text: string): bigint | null {
  let addr = text
  const pct = addr.indexOf('%')
  if (pct !== -1) {
    const zone = addr.slice(pct + 1)
    if (!zone || zone.includes('%')) return null
    addr = addr.slice(0, pct)
  }
  const parts = addr.split(':')
  if (parts.length < 3) return null
  if (parts[parts.length - 1].includes('.')) {
    const v4 = parseIpv4(parts.pop()!)
    if (v4 === null) return null
    parts.push((v4 >> 16n).toString(16), (v4 & 0xffffn).toString(16))
  }
  if (parts.length > 9) return null

  let skipIndex: number | null = null
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skipIndex !== null) return null
      skipIndex = i
    }
  }
  let hi: number
  let lo: number
  let skipped: number
  if (skipIndex !== null) {
    hi = skipIndex
    lo = parts.length - skipIndex - 1
    if (!parts[0]) { hi -= 1; if (hi) return null }
    if (!parts[parts.length - 1]) { lo -= 1; if (lo) return null }
    skipped = 8 - (hi + lo)
    if (skipped < 1) return null
  } else {
    if (parts.length !== 8 || !parts[0] || !parts[parts.length - 1]) return null
    hi = parts.length
    lo = 0
    skipped = 0
  }

  let value = 0n
  const hextet = (p: string): bigint | null => (/^[0-9a-fA-F]{1,4}$/.test(p) ? BigInt(parseInt(p, 16)) : null)
  for (let i = 0; i < hi; i++) {
    const h = hextet(parts[i])
    if (h === null) return null
    value = (value << 16n) | h
  }
  value <<= BigInt(16 * skipped)
  for (let i = -lo; i < 0; i++) {
    const h = hextet(parts[parts.length + i])
    if (h === null) return null
    value = (value << 16n) | h
  }
  return value
}

/** `ipaddress.ip_address`: IPv4 first, then IPv6. */
function parseIp(text: string): Ip | null {
  const v4 = parseIpv4(text)
  if (v4 !== null) return { version: 4, value: v4 }
  const v6 = parseIpv6(text)
  return v6 !== null ? { version: 6, value: v6 } : null
}

/** A contiguous mask's prefix length, or null (`_prefix_from_ip_int`). */
function prefixFromMask(mask: bigint, bits: number): number | null {
  for (let prefix = 0; prefix <= bits; prefix++) {
    if (mask === ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix)) return prefix
  }
  return null
}

/**
 * `ipaddress.ip_network(entry, strict=False)` as a containment test: a prefix
 * length (IPv4 and IPv6), or an IPv4 netmask or hostmask. null when it is not a network.
 */
function parseNetwork(entry: string): { version: 4 | 6; base: bigint; prefix: number } | null {
  const pieces = entry.split('/')
  if (pieces.length > 2) return null
  const ip = parseIp(pieces[0])
  if (!ip) return null
  const bits = ip.version === 4 ? IPV4_BITS : IPV6_BITS
  let prefix = bits
  if (pieces.length === 2) {
    const arg = pieces[1]
    if (/^\d+$/.test(arg)) {
      prefix = Number(arg)
      if (prefix > bits) return null
    } else if (ip.version === 4) {
      const mask = parseIpv4(arg)
      if (mask === null) return null
      const asNetmask = prefixFromMask(mask, bits)
      const asHostmask = asNetmask === null
        ? prefixFromMask(mask ^ ((1n << BigInt(bits)) - 1n), bits)
        : null
      const resolved = asNetmask ?? asHostmask
      if (resolved === null) return null
      prefix = resolved
    } else {
      return null
    }
  }
  return { version: ip.version, base: ip.value, prefix }
}

function inNetwork(address: Ip, network: { version: 4 | 6; base: bigint; prefix: number }): boolean {
  if (address.version !== network.version) return false
  const bits = network.version === 4 ? IPV4_BITS : IPV6_BITS
  const shift = BigInt(bits - network.prefix)
  return (address.value >> shift) === (network.base >> shift)
}

/** The hostname Python's `urlsplit(url).hostname` gives, without lower-casing. */
function urlHostname(url: string): string {
  let rest = url
  const colon = rest.indexOf(':')
  if (colon > 0 && /^[A-Za-z][A-Za-z0-9+.-]*$/.test(rest.slice(0, colon))) rest = rest.slice(colon + 1)
  if (!rest.startsWith('//')) return ''
  rest = rest.slice(2)
  const end = rest.search(/[/?#]/)
  const netloc = end === -1 ? rest : rest.slice(0, end)
  const hostinfo = netloc.slice(netloc.lastIndexOf('@') + 1)
  const open = hostinfo.indexOf('[')
  if (open !== -1) return hostinfo.slice(open + 1).split(']')[0]
  return hostinfo.split(':')[0]
}

/** `_normalize_host`: lower case, without scheme, path, port, IPv6 brackets or trailing dot. */
export function normalizeRoeHost(value: unknown): string {
  if (typeof value !== 'string') return ''
  let host = value.trim()
  if (host.includes('://')) host = urlHostname(host)
  else if (host.startsWith('[')) host = host.slice(1).split(']')[0]
  else if (host.split(':').length === 2) host = host.split(':')[0]
  return host.trim().replace(/\.+$/, '').toLowerCase()
}

/** `_normalize_scope_entry`: `*.domain` and CIDRs keep their shape. */
export function normalizeRoeEntry(value: unknown): string {
  if (typeof value !== 'string') return ''
  const entry = value.trim()
  if (entry.startsWith('*.')) return `*.${normalizeRoeHost(entry.slice(2))}`
  if (entry.includes('/') && !entry.includes('://')) return entry.toLowerCase()
  return normalizeRoeHost(entry)
}

/**
 * True when `host` matches an RoE exclusion: an exact host or IP; a domain,
 * which also excludes its subdomains; `*.domain`, which excludes its
 * subdomains only; or a CIDR. Case, port, scheme, path and a trailing dot are
 * ignored on both sides, and an IPv6 address matches in any spelling. A bare
 * string suffix is never an IP rule: `0.5` does not exclude `10.0.0.5`.
 */
export function isRoeExcluded(host: unknown, excluded: readonly unknown[]): boolean {
  const h = normalizeRoeHost(host)
  if (!h) return false
  const address = parseIp(h)
  for (const value of excluded) {
    const entry = normalizeRoeEntry(value)
    if (!entry) continue
    if (entry.startsWith('*.')) {
      if (h.endsWith(entry.slice(1))) return true
    } else if (entry.includes('/') || address !== null) {
      const network = parseNetwork(entry)
      if (address !== null && network !== null && inNetwork(address, network)) return true
    } else if (h === entry || h.endsWith(`.${entry}`)) {
      return true
    }
  }
  return false
}
