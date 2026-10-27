/**
 * Links from a project's nodes to the global reference catalogue (CVE,
 * MitreData, Capec), carried through exports and scan-version snapshots
 * (plan 09.5).
 *
 * The catalogue carries no project_id: one CVE node is shared by every tenant
 * (graph_db/mixins/base_mixin.py), and a project file is user-supplied input, so
 * it must never create or overwrite one. Exports and snapshots therefore leave
 * the NODES out, which used to drop every edge to them as well (HAS_CVE,
 * INCLUDES_CVE, HAS_KNOWN_CVE, EXPLOITED_CVE, the CWE and CAPEC links). A link
 * record keeps such an edge as the project node's export id plus the reference
 * node's natural key; a restore MATCHes that node by its key, never MERGEs or
 * SETs it, and skips the link when the node is missing. The next scan recreates
 * it from its own feed.
 */
import type { Session } from 'neo4j-driver'

/** Each reference label's natural key; kept equal to GLOBAL_REFERENCE_LABELS. */
export const REFERENCE_KEY_PROPERTY = { CVE: 'id', MitreData: 'id', Capec: 'capec_id' } as const
export type ReferenceLabel = keyof typeof REFERENCE_KEY_PROPERTY
const REFERENCE_LABELS = Object.keys(REFERENCE_KEY_PROPERTY) as ReferenceLabel[]

const REFERENCE_KEY_PATTERN: Record<ReferenceLabel, RegExp> = {
  CVE: /^CVE-\d{4}-\d{4,}$/,
  // "<cve>-<cwe>", graph_db/mixins/recon/vuln_mixin.py
  MitreData: /^CVE-\d{4}-\d{4,}-CWE-\d+$/,
  Capec: /^CAPEC-\d+$/,
}
const RELATIONSHIP_TYPE = /^[A-Z][A-Z0-9_]{0,63}$/

export const REFERENCE_LINKS_BUNDLE_PATH = 'neo4j/reference_links.json'

/** Exactly one of the two export ids is null: that end is the reference node. */
export interface ReferenceLink {
  startExportId: string | null
  endExportId: string | null
  type: string
  refLabel: ReferenceLabel
  refKey: string
  properties: Record<string, unknown>
}

export interface CapturedRelationship {
  startExportId: string
  endExportId: string
  type: string
  properties: Record<string, unknown>
}

function refEnd(v: 'a' | 'b', prefix: 'start' | 'end'): string {
  const label = REFERENCE_LABELS.map(l => `WHEN ${v}:${l} THEN '${l}'`).join(' ')
  const key = REFERENCE_LABELS.map(l => `WHEN ${v}:${l} THEN ${v}.${REFERENCE_KEY_PROPERTY[l]}`).join(' ')
  return `CASE ${label} END AS ${prefix}RefLabel, CASE ${key} END AS ${prefix}RefKey`
}

/**
 * Every relationship with an end in the project, with each end's reference
 * label and key when it is a catalogue node. Shared by the export and the
 * snapshot capture, so the two stay the same restore format.
 */
export const PROJECT_RELATIONSHIPS_CYPHER =
  `MATCH (a)-[r]->(b)
   WHERE a.project_id = $pid OR b.project_id = $pid
   RETURN elementId(a) as startId, elementId(b) as endId,
          type(r) as relType, properties(r) as relProps,
          ${refEnd('a', 'start')}, ${refEnd('b', 'end')}`

/** For a node query: leave the catalogue out even where a legacy node still carries a project_id. */
export const REFERENCE_LABELS_PARAM = { referenceLabels: REFERENCE_LABELS }
export const NOT_A_REFERENCE_NODE = 'NONE(l IN labels(n) WHERE l IN $referenceLabels)'

export function isReferenceNode(labels: readonly string[]): boolean {
  return labels.some(l => (REFERENCE_LABELS as string[]).includes(l))
}

/** A link record from any input, or null when it is not one we can trust. */
export function referenceLinkOf(raw: unknown): ReferenceLink | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const r = raw as Record<string, unknown>
  const label = r.refLabel as ReferenceLabel
  if (!REFERENCE_LABELS.includes(label)) return null
  if (typeof r.refKey !== 'string' || !REFERENCE_KEY_PATTERN[label].test(r.refKey)) return null
  if (typeof r.type !== 'string' || !RELATIONSHIP_TYPE.test(r.type)) return null
  const start = typeof r.startExportId === 'string' && r.startExportId ? r.startExportId : null
  const end = typeof r.endExportId === 'string' && r.endExportId ? r.endExportId : null
  if ((start === null) === (end === null)) return null
  const props = r.properties ?? {}
  if (typeof props !== 'object' || Array.isArray(props)) return null
  return {
    startExportId: start, endExportId: end, type: r.type,
    refLabel: label, refKey: r.refKey, properties: props as Record<string, unknown>,
  }
}

/**
 * Sort captured relationship records into project-internal relationships and
 * link records. An edge whose far end is neither a captured node nor a valid
 * catalogue node is dropped, as before.
 */
export function splitCapturedRelationships(
  records: { get: (key: string) => unknown }[],
  exportIds: ReadonlyMap<string, string>,
  serialize: (props: Record<string, unknown>) => Record<string, unknown>,
): { relationships: CapturedRelationship[]; referenceLinks: ReferenceLink[] } {
  const relationships: CapturedRelationship[] = []
  const referenceLinks: ReferenceLink[] = []
  for (const record of records) {
    const start = exportIds.get(record.get('startId') as string)
    const end = exportIds.get(record.get('endId') as string)
    const type = record.get('relType') as string
    const properties = serialize((record.get('relProps') as Record<string, unknown>) || {})
    if (start && end) {
      relationships.push({ startExportId: start, endExportId: end, type, properties })
      continue
    }
    const far = start ? 'end' : end ? 'start' : null
    if (!far) continue
    const link = referenceLinkOf({
      startExportId: start ?? null, endExportId: end ?? null, type, properties,
      refLabel: record.get(`${far}RefLabel`), refKey: record.get(`${far}RefKey`),
    })
    if (link) referenceLinks.push(link)
  }
  return { relationships, referenceLinks }
}

/**
 * A payload that carries catalogue NODES (a snapshot or bundle from before they
 * lost their tenant stamp) stored the edges to them as ordinary relationships.
 * Those nodes are never restored, so each such edge becomes a link record to
 * the node's natural key; an edge between two catalogue nodes is dropped, the
 * database already holds the catalogue's own links.
 */
export function carriedReferenceEdgesToLinks<R extends CapturedRelationship>(
  nodes: readonly { labels: string[]; properties: Record<string, unknown>; _exportId: string }[],
  relationships: readonly R[],
): { relationships: R[]; referenceLinks: ReferenceLink[] } {
  const refs = new Map<string, { refLabel: ReferenceLabel; refKey: unknown }>()
  for (const node of nodes) {
    const label = REFERENCE_LABELS.find(l => node.labels.includes(l))
    if (label) refs.set(node._exportId, { refLabel: label, refKey: node.properties[REFERENCE_KEY_PROPERTY[label]] })
  }
  if (refs.size === 0) return { relationships: [...relationships], referenceLinks: [] }
  const kept: R[] = []
  const referenceLinks: ReferenceLink[] = []
  for (const rel of relationships) {
    const start = refs.get(rel.startExportId)
    const end = refs.get(rel.endExportId)
    if (!start && !end) {
      kept.push(rel)
      continue
    }
    if (start && end) continue
    const link = referenceLinkOf({
      startExportId: start ? null : rel.startExportId, endExportId: end ? null : rel.endExportId,
      type: rel.type, properties: rel.properties, ...(start ?? end),
    })
    if (link) referenceLinks.push(link)
  }
  return { relationships: kept, referenceLinks }
}

/**
 * Recreate the links of restored project nodes (still carrying `_exportId`) to
 * EXISTING catalogue nodes. The label and key property in each query come from
 * REFERENCE_KEY_PROPERTY, never from the input; the key, the type and the
 * properties are parameters.
 */
export async function restoreReferenceLinks(
  session: Session,
  links: readonly unknown[],
  projectId: string,
  batchSize = 500,
): Promise<{ restored: number; skipped: number }> {
  const groups = new Map<string, { label: ReferenceLabel; outgoing: boolean; rows: Record<string, unknown>[] }>()
  for (const raw of links) {
    const link = referenceLinkOf(raw)
    if (!link) continue
    const outgoing = link.endExportId === null
    const key = `${link.refLabel}:${outgoing}`
    if (!groups.has(key)) groups.set(key, { label: link.refLabel, outgoing, rows: [] })
    groups.get(key)!.rows.push({
      localExportId: outgoing ? link.startExportId : link.endExportId,
      refKey: link.refKey, type: link.type, properties: link.properties,
    })
  }

  let restored = 0
  for (const { label, outgoing, rows } of groups.values()) {
    const [from, to] = outgoing ? ['local', 'ref'] : ['ref', 'local']
    for (let i = 0; i < rows.length; i += batchSize) {
      const result = await session.run(
        `UNWIND $links AS link
         MATCH (local {_exportId: link.localExportId, project_id: $pid})
         MATCH (ref:${label} {${REFERENCE_KEY_PROPERTY[label]}: link.refKey})
         CALL apoc.create.relationship(${from}, link.type, link.properties, ${to}) YIELD rel
         RETURN count(rel) AS created`,
        { links: rows.slice(i, i + batchSize), pid: projectId }
      )
      const created = result.records[0]?.get('created')
      restored += typeof created === 'number' ? created : Number((created as { low?: number })?.low ?? 0)
    }
  }
  return { restored, skipped: links.length - restored }
}
