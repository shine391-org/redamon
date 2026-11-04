/**
 * The error answer of the graph routes: a fixed sentence and a code, never the
 * Neo4j message, which quotes the Cypher and the target data in it. The code is
 * the server's `Neo.*` status or the driver's own (`ServiceUnavailable`,
 * `SessionExpired`), so a stopped database reads apart from a dropped session.
 */
import type { NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'

export function graphError(err: unknown, message: string, log: string): NextResponse {
  return internalError(err, message, { log })
}
