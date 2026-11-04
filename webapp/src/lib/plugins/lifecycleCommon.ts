import type { PluginInstall } from '@prisma/client'

/**
 * A lifecycle refusal with the HTTP status and code the routes answer with. `extra` holds
 * safe fields for the answer, such as `committed: true` for a failure after the commit.
 */
export class LifecycleError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: string[],
    readonly extra?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'LifecycleError'
  }
}

/**
 * A purge deletes a plugin's data for every user and project, so it needs an export made
 * shortly before: the export route records when one was downloaded.
 */
export const EXPORT_FRESH_MS = 60 * 60 * 1000
export const exportMarkerKey = (pluginId: string) => `export:${pluginId}`

/** The statuses of an installed plugin: what enable, disable, update and uninstall start from. */
export const INSTALLED_STATUSES = ['ready', 'failed', 'incompatible'] as const

export interface InstallView {
  pluginId: string
  status: string
  enabled: boolean
  activeVersion: string | null
  previousVersion: string | null
  pendingVersion: string | null
  dataVersion: number
  grantedPermissions: string[]
  lastError: string | null
  revokedReason: string | null
  installedAt: string | null
  installedBy: string | null
  operationKind: string | null
}

export function installView(row: PluginInstall): InstallView {
  return {
    pluginId: row.pluginId,
    status: row.status,
    enabled: row.enabled,
    activeVersion: row.activeVersion,
    previousVersion: row.previousVersion,
    pendingVersion: row.pendingVersion,
    dataVersion: row.dataVersion,
    grantedPermissions: Array.isArray(row.grantedPermissions) ? (row.grantedPermissions as string[]) : [],
    lastError: row.lastError,
    revokedReason: row.revokedReason,
    installedAt: row.installedAt ? new Date(row.installedAt).toISOString() : null,
    installedBy: row.installedBy,
    operationKind: row.operationKind,
  }
}
