import { NextRequest, NextResponse } from 'next/server'
import { archiveMaxBytes } from '@/lib/plugins/fetchRemote'
import { offlineInstall } from '@/lib/plugins/lifecycle'
import { errorResponse, lifecycleErrorResponse, pluginRoute, requirePluginAdmin } from '@/lib/plugins/lifecycleRoutes'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'

/**
 * POST /api/plugins/offline-install (admin, same origin, multipart: `archive`, `catalog`,
 * `signature`, `acceptedPermissions` as JSON, optional `restoreOverrides`): the same checks
 * as a download (lib/plugins/lifecycle.ts offlineInstall).
 *
 * Content-Length is checked before the body is parsed, and the archive's own size after it;
 * sizes declared inside the archive are never trusted (the project import's JSZip limits are
 * not a model here).
 */
export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const FORM_OVERHEAD = 2 * 1024 * 1024
// Next passes a route only the first 10 MiB of a body that goes through middleware
// (`proxyClientMaxBodySize`, unset in next.config.ts), so a larger form arrives cut short.
const MIDDLEWARE_BODY_MAX_BYTES = 10 * 1024 * 1024
const CATALOG_MAX_BYTES = 1_048_576
const SIGNATURE_MAX_BYTES = 4096

async function bytesOf(form: FormData, name: string): Promise<Buffer | null> {
  const v = form.get(name)
  if (!v || typeof v === 'string') return null
  return Buffer.from(await v.arrayBuffer())
}

export const POST = pluginRoute('offline install', 'The plugin operation failed; see the webapp log.', async (request: NextRequest) => {
  const admin = await requirePluginAdmin()
  if (admin instanceof NextResponse) return admin
  if (!sameOrigin(request)) return crossOriginResponse(request)
  if (!(request.headers.get('content-type') ?? '').toLowerCase().startsWith('multipart/form-data')) {
    return errorResponse(415, 'unsupported_media_type', 'Send the archive, the catalog and its signature as multipart/form-data.')
  }
  const declared = Number(request.headers.get('content-length'))
  if (!request.headers.has('content-length') || !Number.isFinite(declared) || declared < 0) {
    return errorResponse(411, 'length_required', 'The upload must declare its Content-Length.')
  }
  const cap = Math.min(archiveMaxBytes() + FORM_OVERHEAD, MIDDLEWARE_BODY_MAX_BYTES)
  if (declared > cap) {
    return errorResponse(
      413,
      'upload_too_large',
      `The upload is limited to ${cap} bytes; a larger plugin installs from the catalog download.`,
    )
  }

  let form: FormData
  try {
    form = await request.formData()
  } catch {
    return errorResponse(400, 'invalid_request', 'The upload is not valid multipart/form-data.')
  }
  const [archive, catalog, signature] = await Promise.all([bytesOf(form, 'archive'), bytesOf(form, 'catalog'), bytesOf(form, 'signature')])
  if (!archive || !catalog || !signature) {
    return errorResponse(400, 'invalid_request', 'Upload the archive, catalog.json and catalog.json.sig together.')
  }
  if (archive.length > archiveMaxBytes()) {
    return errorResponse(413, 'archive_too_large', `The archive is limited to ${archiveMaxBytes()} bytes.`)
  }
  if (catalog.length > CATALOG_MAX_BYTES || signature.length > SIGNATURE_MAX_BYTES) {
    return errorResponse(413, 'upload_too_large', 'The catalog or its signature is too large.')
  }
  let acceptedPermissions: unknown
  try {
    acceptedPermissions = JSON.parse(String(form.get('acceptedPermissions') ?? ''))
  } catch {
    acceptedPermissions = null
  }
  const restore = form.get('restoreOverrides')
  const started = Date.now()
  try {
    const out = await offlineInstall(
      {
        archive,
        catalog,
        signature,
        acceptedPermissions: acceptedPermissions as string[],
        restoreOverrides: restore === 'true' ? true : restore === 'false' ? false : undefined,
      },
      admin.userId,
    )
    console.log(`[plugins] offline install by ${admin.userId}: ok in ${Date.now() - started} ms`)
    return NextResponse.json(out, { headers: { 'Cache-Control': 'no-store' } })
  } catch (e) {
    const res = lifecycleErrorResponse(e, 'offline install')
    console.warn(`[plugins] offline install by ${admin.userId}: ${res.status} in ${Date.now() - started} ms`)
    return res
  }
})
