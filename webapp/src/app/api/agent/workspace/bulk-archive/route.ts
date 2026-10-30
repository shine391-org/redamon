import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'

export const runtime = 'nodejs'
export const maxDuration = 60

const FAILED = 'Failed to build archive'

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: { projectId?: string; paths?: string[]; format?: string; archiveName?: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  if (!body.projectId || !Array.isArray(body.paths) || body.paths.length === 0) {
    return NextResponse.json({ error: 'projectId + non-empty paths required' }, { status: 400 })
  }
  const __denied = await guardProject(body.projectId || '')
  if (__denied) return __denied

  const call = await callAgent('/workspace/bulk-archive', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, FAILED, { timeoutMs: 60_000 })
  if (!call.ok) return call.response
  const resp = call.res
  if (!resp.ok) return agentErrorResponse(resp, FAILED)
  const buffer = await resp.arrayBuffer()
  const contentDisposition = resp.headers.get('Content-Disposition') || ''
  const contentType = resp.headers.get('Content-Type') || 'application/octet-stream'
  return new NextResponse(buffer, {
    status: 200,
    headers: {
      'Content-Type': contentType,
      'Content-Disposition': contentDisposition,
      'Content-Length': String(buffer.byteLength),
      'Cache-Control': 'no-cache',
    },
  })
})
