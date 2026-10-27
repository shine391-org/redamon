/**
 * Building the orchestrator start body for one TruffleHog source.
 *
 * Shared by the two paths that can start a scan — the Start button
 * (`/api/trufflehog/[projectId]/start`) and the queue dispatcher
 * (`dispatchStart`) — because they must produce the SAME body. A queued job that
 * loses its source runs the wrong config, and a queued job that loses its
 * credential fails with an opaque registry error long after the operator left.
 *
 * Credentials are read here, server-side, from `UserSettings` and passed to the
 * orchestrator in the request body. They are never stored on the profile or the
 * project row, both of which are spread verbatim into `project.json` inside the
 * downloadable export zip.
 */

import prisma from '@/lib/prisma'
import {
  TRUFFLEHOG_CREDENTIAL_FIELDS,
  getTrufflehogSource,
  resolveMissingCredentials,
  validateTrufflehogConfig,
} from '@/lib/trufflehogSources'

export interface TrufflehogStartBody {
  project_id: string
  user_id: string
  webapp_api_url: string
  source: string
  config: Record<string, unknown>
  common: Record<string, unknown>
  secrets: Record<string, string>
}

export type TrufflehogStartResolution =
  | { ok: true; body: TrufflehogStartBody; source: string }
  | { ok: false; status: number; error: string }

/**
 * Shared options that apply to every source (A.1). They live on `Project`, so
 * one change applies to all sources — and, importantly, editing them does not
 * invalidate a queued job for an unrelated source's profile.
 *
 * The fallbacks equal the Prisma `@default`s so a project row saved before a
 * field existed does not send `undefined` to the orchestrator.
 */
export function buildTrufflehogCommon(project: Record<string, unknown>): Record<string, unknown> {
  const num = (v: unknown, d: number) => (typeof v === 'number' && Number.isFinite(v) ? v : d)
  const str = (v: unknown, d = '') => (typeof v === 'string' ? v : d)
  return {
    // Verification off means NOTHING was checked; the scanner marks every
    // finding `unverified` rather than `rejected` because of this flag.
    skipVerification: project.trufflehogNoVerification === true,
    resultTypes: str(project.trufflehogResultTypes, 'verified,unverified,unknown')
      .split(',').map(s => s.trim()).filter(Boolean),
    concurrency: num(project.trufflehogConcurrency, 8),
    includeDetectors: str(project.trufflehogIncludeDetectors),
    excludeDetectors: str(project.trufflehogExcludeDetectors),
    filterEntropy: str(project.trufflehogFilterEntropy),
    detectorTimeout: str(project.trufflehogDetectorTimeout),
    maxDecodeDepth: num(project.trufflehogMaxDecodeDepth, 5),
    forceSkipBinaries: project.trufflehogForceSkipBinaries === true,
    forceSkipArchives: project.trufflehogForceSkipArchives === true,
    archiveMaxSize: str(project.trufflehogArchiveMaxSize),
    archiveMaxDepth: num(project.trufflehogArchiveMaxDepth, 0),
    archiveTimeout: str(project.trufflehogArchiveTimeout),
    allowVerificationOverlap: project.trufflehogAllowVerificationOverlap === true,
    dropUnverifiedJwtResults: project.trufflehogDropUnverifiedJwt === true,
  }
}

/** The UserSettings columns this feature reads, as a Prisma `select`. */
const CREDENTIAL_SELECT = Object.fromEntries(
  TRUFFLEHOG_CREDENTIAL_FIELDS.map(f => [f, true]),
) as Record<string, true>

/**
 * Resolve a profile into a ready-to-post orchestrator body, or an error.
 *
 * `profileId` identifies the profile; `source` is accepted as a fallback for a
 * queued job enqueued before the profile id was recorded. Every failure is a
 * 4xx the caller surfaces verbatim — the orchestrator re-runs the same checks,
 * so this is the fast path, never the only gate.
 */
export async function resolveTrufflehogStart(
  projectId: string,
  opts: { profileId?: string; source?: string; webappUrl: string },
): Promise<TrufflehogStartResolution> {
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true, userId: true,
      trufflehogNoVerification: true, trufflehogResultTypes: true,
      trufflehogConcurrency: true, trufflehogIncludeDetectors: true,
      trufflehogExcludeDetectors: true, trufflehogFilterEntropy: true,
      trufflehogDetectorTimeout: true, trufflehogMaxDecodeDepth: true,
      trufflehogForceSkipBinaries: true, trufflehogForceSkipArchives: true,
      trufflehogArchiveMaxSize: true, trufflehogArchiveMaxDepth: true,
      trufflehogArchiveTimeout: true, trufflehogAllowVerificationOverlap: true,
      trufflehogDropUnverifiedJwt: true,
    },
  })
  if (!project) return { ok: false, status: 404, error: 'Project not found' }

  const profile = opts.profileId
    ? await prisma.trufflehogScanProfile.findFirst({
        where: { id: opts.profileId, projectId },
        select: { id: true, source: true, config: true },
      })
    : opts.source
      ? await prisma.trufflehogScanProfile.findUnique({
          where: { projectId_source: { projectId, source: opts.source } },
          select: { id: true, source: true, config: true },
        })
      : null

  if (!profile) {
    return {
      ok: false, status: 404,
      error: 'No Secret Multiscanner scan profile found for this source. Configure the source first.',
    }
  }

  const src = getTrufflehogSource(profile.source)
  if (!src) return { ok: false, status: 400, error: `Unknown Secret Multiscanner source: ${profile.source}` }

  const config = (profile.config ?? {}) as Record<string, unknown>
  const errors = validateTrufflehogConfig(src.id, config)
  if (errors.length) return { ok: false, status: 400, error: errors.join('; ') }

  const settings = await prisma.userSettings.findUnique({
    where: { userId: project.userId },
    select: CREDENTIAL_SELECT,
  })

  // Re-checked at dispatch, not only when the card was rendered: a queued job
  // can reach here long after the operator cleared the key.
  const missing = resolveMissingCredentials(src.id, config, settings as Record<string, unknown> | null)
  if (missing.length) {
    return {
      ok: false, status: 400,
      error: `${src.label} requires ${missing.map(m => m.label).join(', ')}. `
        + 'Set it in Global Settings > API Keys > Secret Multiscanner.',
    }
  }

  // Only the credentials THIS source uses. The container gets nothing else.
  const secrets: Record<string, string> = {}
  for (const cred of src.credentials) {
    const value = (settings as Record<string, unknown> | null)?.[cred.settingsKey]
    if (typeof value === 'string' && value.trim()) secrets[cred.settingsKey] = value
  }

  return {
    ok: true,
    source: src.id,
    body: {
      project_id: projectId,
      user_id: project.userId,
      webapp_api_url: opts.webappUrl,
      source: src.id,
      config,
      common: buildTrufflehogCommon(project as unknown as Record<string, unknown>),
      secrets,
    },
  }
}

/**
 * The scan-steering settings a TruffleHog job carries OUTSIDE the Project row.
 *
 * The per-source target moved to `TrufflehogScanProfile`, so without this the
 * C-4 fingerprint would cover only the shared options: re-pointing a queued
 * Docker scan at a different namespace would not invalidate it, and the job
 * would run a config the operator never confirmed.
 *
 * Returns `{}` for a non-trufflehog kind, and a marker for a profile that has
 * since been deleted — a missing profile must still CHANGE the hash, or the job
 * would dispatch as if nothing happened.
 */
export async function resolveTrufflehogFingerprintExtra(
  kind: string,
  projectId: string,
  payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (kind !== 'trufflehog') return {}

  const profileId = typeof payload.profile_id === 'string' ? payload.profile_id : ''
  const source = typeof payload.source === 'string' ? payload.source : ''
  if (!profileId && !source) return { trufflehogProfile: null }

  const profile = profileId
    ? await prisma.trufflehogScanProfile.findFirst({
        where: { id: profileId, projectId },
        select: { source: true, config: true },
      })
    : await prisma.trufflehogScanProfile.findUnique({
        where: { projectId_source: { projectId, source } },
        select: { source: true, config: true },
      })

  if (!profile) return { trufflehogProfile: 'missing' }
  return { trufflehogProfileSource: profile.source, trufflehogProfileConfig: profile.config }
}
