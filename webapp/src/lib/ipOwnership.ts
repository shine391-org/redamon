/**
 * The IP attribution tag recon writes on IP nodes (plan 11): shared_edge, a CDN
 * edge serving many tenants; dedicated, its default certificate covers a target
 * domain; unknown, neither could be shown. Never "not ours". An IP written
 * before the step existed has no tag, which reads as "not checked yet", never
 * as unknown.
 */

export type IpOwnership = 'shared_edge' | 'dedicated' | 'unknown'

/** The raw keys the drawer's Ownership line replaces in its property list. */
export const OWNERSHIP_PROPERTIES = ['ownership', 'ownership_reasons'] as const

const LABELS: Record<IpOwnership, string> = {
  shared_edge: 'Shared edge',
  dedicated: 'Dedicated',
  unknown: 'Unknown',
}

export function readOwnership(props: Record<string, unknown> | null | undefined): IpOwnership | null {
  const tag = props?.ownership
  return typeof tag === 'string' && tag in LABELS ? (tag as IpOwnership) : null
}

/** The report's Ownership cell: empty for an IP no run attributed yet. */
export function ownershipLabel(tag: unknown): string {
  return typeof tag === 'string' && tag in LABELS ? LABELS[tag as IpOwnership] : ''
}

/** The drawer's line, e.g. "Shared edge (Cloudflare): in a published CDN edge range; ...". */
export function ownershipLine(props: Record<string, unknown> | null | undefined): string {
  const tag = readOwnership(props)
  if (!tag) return 'not checked yet'
  const cdn = tag === 'shared_edge' && typeof props?.cdn_name === 'string' && props.cdn_name
    ? ` (${props.cdn_name.charAt(0).toUpperCase()}${props.cdn_name.slice(1)})`
    : ''
  const reasons = Array.isArray(props?.ownership_reasons)
    ? props.ownership_reasons.filter((r): r is string => typeof r === 'string' && r.length > 0)
    : []
  return `${LABELS[tag]}${cdn}${reasons.length ? `: ${reasons.join('; ')}` : ''}`
}
