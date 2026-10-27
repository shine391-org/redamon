/**
 * The Neo4j section of a project export: the same node and relationship reads
 * as a Scan Timeline snapshot (lib/scanSnapshot.ts), without the session-label
 * exclusion, so an export is re-importable through lib/graphRestore.ts.
 */
import { randomUUID } from 'crypto'
import type { Session } from 'neo4j-driver'
import { serializeGraphProperties } from '@/lib/graphSerialize'
import {
  NOT_A_REFERENCE_NODE,
  PROJECT_RELATIONSHIPS_CYPHER,
  REFERENCE_LABELS_PARAM,
  splitCapturedRelationships,
  type CapturedRelationship,
  type ReferenceLink,
} from '@/lib/graphReferenceLinks'

export interface ExportedGraph {
  nodes: Array<{ labels: string[]; properties: Record<string, unknown>; _exportId: string }>
  relationships: CapturedRelationship[]
  referenceLinks: ReferenceLink[]
}

export async function exportProjectGraph(session: Session, projectId: string): Promise<ExportedGraph> {
  const nodesResult = await session.run(
    `MATCH (n) WHERE n.project_id = $pid AND ${NOT_A_REFERENCE_NODE}
     RETURN labels(n) as labels, properties(n) as props, elementId(n) as eid`,
    { pid: projectId, ...REFERENCE_LABELS_PARAM }
  )

  const elementIdToExportId = new Map<string, string>()
  const nodes = nodesResult.records.map(record => {
    const exportId = randomUUID()
    elementIdToExportId.set(record.get('eid') as string, exportId)
    return {
      labels: record.get('labels') as string[],
      properties: serializeGraphProperties(record.get('props') as Record<string, unknown>),
      _exportId: exportId,
    }
  })

  const relsResult = await session.run(PROJECT_RELATIONSHIPS_CYPHER, { pid: projectId })
  return {
    nodes,
    ...splitCapturedRelationships(relsResult.records, elementIdToExportId, serializeGraphProperties),
  }
}
