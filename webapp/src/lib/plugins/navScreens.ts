import fs from 'node:fs/promises'
import path from 'node:path'
import { safeErrorCode } from '@/lib/routeErrors'
import { rowContributions } from './contributions'
import { isValidPluginId } from './ids'
import { screenPathFromSegments } from './navPaths'
import { findInstall } from './registry'
import { SCREEN_PATH_RE } from './schemas/common'
import { versionPath } from './staging'

/**
 * What a plugin's nav page draws (design §6 `nav` point): the nav screen, or another screen
 * the manifest lists, read from the active version on the plugins volume. null means 404.
 */
export const SCREEN_FILE_MAX_BYTES = 256 * 1024

interface NavHeader {
  pluginId: string
  displayName: string
  navLabel: string
  navIcon: string
  screenPath: string
}

export type NavScreen = (NavHeader & { kind: 'ok'; screen: unknown }) | (NavHeader & { kind: 'unreadable'; reason: string })

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

/** Missing is only ENOENT: a permission or I/O error names its errno, which a missing file would hide. */
function unreadableReason(e: unknown): string {
  if (e instanceof SyntaxError) return 'the screen file is not JSON'
  const code = safeErrorCode(e)
  if (code === 'ENOENT') return 'the screen file is missing'
  return `the screen file could not be read (${code})`
}

export async function resolveNavScreen(pluginId: string, segments: readonly string[] | undefined): Promise<NavScreen | null> {
  if (!isValidPluginId(pluginId)) return null
  const row = await findInstall(pluginId)
  if (!row || !row.activeVersion) return null
  const c = rowContributions(row)
  if (!c?.nav) return null

  const screenPath = segments && segments.length > 0 ? screenPathFromSegments(segments) : c.nav.screen
  if (!screenPath || !SCREEN_PATH_RE.test(screenPath)) return null
  const listed = isObj(row.manifest) && Array.isArray(row.manifest.screens) ? row.manifest.screens : []
  if (!listed.includes(screenPath)) return null

  const header: NavHeader = { pluginId, displayName: c.displayName, navLabel: c.nav.label, navIcon: c.nav.icon, screenPath }
  const root = versionPath(pluginId, row.activeVersion)
  const file = path.join(root, screenPath)
  // The path rules above already keep it inside the version folder; this holds if they change.
  if (!file.startsWith(root + path.sep)) return null

  try {
    const stat = await fs.stat(file)
    if (stat.size > SCREEN_FILE_MAX_BYTES) return { ...header, kind: 'unreadable', reason: 'the screen file is too large' }
    return { ...header, kind: 'ok', screen: JSON.parse(await fs.readFile(file, 'utf8')) }
  } catch (e) {
    console.warn(`[plugins] nav screen plugin=${pluginId} screen=${screenPath} unreadable:`, e instanceof Error ? e.message : e)
    return { ...header, kind: 'unreadable', reason: unreadableReason(e) }
  }
}
