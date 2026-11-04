import { NextResponse } from 'next/server'
import { requireEffectiveUser } from '@/lib/access'
import { listContributions } from '@/lib/plugins/contributions'
import { pluginRoute } from '@/lib/plugins/lifecycleRoutes'

/**
 * GET /api/plugins/contributions: the UI every enabled plugin contributes (design §6). Any
 * signed-in user reads it.
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

export const GET = pluginRoute('contributions', 'The plugin items could not be read; see the webapp log.', async () => {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  return NextResponse.json(await listContributions(), { headers: { 'Cache-Control': 'no-store' } })
})
