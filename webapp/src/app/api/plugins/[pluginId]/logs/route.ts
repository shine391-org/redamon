import { NextResponse, type NextRequest } from 'next/server'
import { isValidPluginId } from '@/lib/plugins/ids'
import { errorResponse, lifecycleGet } from '@/lib/plugins/lifecycleRoutes'
import { RunnerError, RunnerUnavailableError, pluginLogs } from '@/lib/plugins/runnerClient'

/** GET /api/plugins/[pluginId]/logs?lines=N (admin): the runner's ring buffer for this plugin. */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export async function GET(request: NextRequest, { params }: { params: Promise<{ pluginId: string }> }) {
  const { pluginId } = await params
  return lifecycleGet(`logs ${pluginId}`, async () => {
    if (!isValidPluginId(pluginId)) return errorResponse(400, 'invalid_plugin_id', 'Invalid plugin id.')
    const asked = Number(request.nextUrl.searchParams.get('lines') ?? '')
    const lines = Number.isFinite(asked) && asked > 0 ? asked : 200
    try {
      return NextResponse.json({ lines: await pluginLogs(pluginId, lines) }, { headers: { 'Cache-Control': 'no-store' } })
    } catch (e) {
      if (e instanceof RunnerUnavailableError) {
        return errorResponse(503, 'runner_unavailable', e.message, undefined, { reason: e.reason, ...(e.proxyCode ? { proxyCode: e.proxyCode } : {}) })
      }
      if (e instanceof RunnerError) return errorResponse(502, e.code, e.message, undefined, { upstreamStatus: e.status })
      throw e
    }
  })
}
