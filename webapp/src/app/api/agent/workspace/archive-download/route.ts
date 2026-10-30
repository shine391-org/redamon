import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'

const FAILED = 'Failed to download archive'

export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  const path = request.nextUrl.searchParams.get('path')
  const format = request.nextUrl.searchParams.get('format') ?? 'tar.gz'

  if (!projectId || !path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  const call = await callAgent(
    `/workspace/archive-download?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}&format=${encodeURIComponent(format)}`,
    {},
    FAILED,
    { timeoutMs: 60_000 },
  )
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
