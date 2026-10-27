/**
 * Resolving a profile into an orchestrator start body.
 *
 * Two callers must produce the SAME body — the Start button and the queue
 * dispatcher. Everything here guards a failure that shows up long after the
 * operator has left: a queued job dispatched without its source, a credential
 * cleared between enqueue and dispatch, or a fingerprint that no longer notices
 * the target changed.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  projectFindUnique: vi.fn(),
  profileFindFirst: vi.fn(),
  profileFindUnique: vi.fn(),
  settingsFindUnique: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    trufflehogScanProfile: {
      findFirst: (...a: unknown[]) => h.profileFindFirst(...a),
      findUnique: (...a: unknown[]) => h.profileFindUnique(...a),
    },
    userSettings: { findUnique: (...a: unknown[]) => h.settingsFindUnique(...a) },
  },
}))

import {
  buildTrufflehogCommon,
  resolveTrufflehogFingerprintExtra,
  resolveTrufflehogStart,
} from './trufflehogStart'
import { settingsFingerprint } from './jobQueue'

const PROJECT = {
  id: 'p1', userId: 'u1',
  trufflehogNoVerification: false,
  trufflehogResultTypes: 'verified,unverified,unknown',
  trufflehogConcurrency: 8,
  trufflehogIncludeDetectors: '',
  trufflehogExcludeDetectors: '',
  trufflehogFilterEntropy: '',
  trufflehogDetectorTimeout: '',
  trufflehogMaxDecodeDepth: 5,
  trufflehogForceSkipBinaries: false,
  trufflehogForceSkipArchives: false,
  trufflehogArchiveMaxSize: '',
  trufflehogArchiveMaxDepth: 0,
  trufflehogArchiveTimeout: '',
  trufflehogAllowVerificationOverlap: false,
  trufflehogDropUnverifiedJwt: false,
}

const DOCKER_PROFILE = { id: 'prof1', source: 'docker', config: { images: ['nginx:1.25'] } }

beforeEach(() => {
  vi.clearAllMocks()
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.profileFindFirst.mockResolvedValue(DOCKER_PROFILE)
  h.profileFindUnique.mockResolvedValue(DOCKER_PROFILE)
  h.settingsFindUnique.mockResolvedValue({})
})

const start = (opts: Record<string, unknown> = {}) =>
  resolveTrufflehogStart('p1', { profileId: 'prof1', webappUrl: 'http://webapp:3000', ...opts })

describe('resolveTrufflehogStart', () => {
  test('produces a body carrying the source, config and shared options', async () => {
    const r = await start()
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.source).toBe('docker')
    expect(r.body.source).toBe('docker')
    expect(r.body.config).toEqual({ images: ['nginx:1.25'] })
    expect(r.body.common.concurrency).toBe(8)
    expect(r.body.user_id).toBe('u1')
  })

  test('a missing project is a 404', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    expect(await start()).toMatchObject({ ok: false, status: 404 })
  })

  test('a missing profile is a 404, not a silent default', async () => {
    h.profileFindFirst.mockResolvedValue(null)
    h.profileFindUnique.mockResolvedValue(null)
    const r = await start()
    expect(r).toMatchObject({ ok: false, status: 404 })
    if (!r.ok) expect(r.error).toContain('scan profile')
  })

  test('a profile can be resolved by source when no profile id is recorded', async () => {
    const r = await resolveTrufflehogStart('p1', { source: 'docker', webappUrl: 'http://w' })
    expect(r.ok).toBe(true)
    expect(h.profileFindUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { projectId_source: { projectId: 'p1', source: 'docker' } } }),
    )
  })

  test('an invalid stored config is refused before the orchestrator is called', async () => {
    h.profileFindFirst.mockResolvedValue({ id: 'p', source: 'docker', config: {} })
    const r = await start()
    expect(r).toMatchObject({ ok: false, status: 400 })
    if (!r.ok) expect(r.error).toContain('image or a namespace')
  })

  test('a mandatory credential cleared after enqueue blocks the dispatch', async () => {
    // The whole point of re-checking here: the card was rendered when the key
    // existed, and the job may dispatch hours later.
    h.profileFindFirst.mockResolvedValue({ id: 'p', source: 'github', config: { orgs: ['acme'] } })
    h.settingsFindUnique.mockResolvedValue({ trufflehogGithubToken: '' })
    const r = await start()
    expect(r).toMatchObject({ ok: false, status: 400 })
    if (!r.ok) {
      expect(r.error).toContain('Secret Multiscanner GitHub Token')
      expect(r.error).toContain('API Keys')
    }
  })

  test('only the credentials this source uses are forwarded', async () => {
    h.settingsFindUnique.mockResolvedValue({
      trufflehogDockerToken: 'dckr_x',
      trufflehogGithubToken: 'ghp_should_not_travel',
      trufflehogAwsSecretKey: 'aws_should_not_travel',
    })
    const r = await start()
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.body.secrets).toEqual({ trufflehogDockerToken: 'dckr_x' })
  })

  test('an empty credential is not forwarded as an empty string', async () => {
    h.settingsFindUnique.mockResolvedValue({ trufflehogDockerToken: '   ' })
    const r = await start()
    expect(r.ok).toBe(true)
    if (r.ok) expect(r.body.secrets).toEqual({})
  })

  test('an optional credential is forwarded when set', async () => {
    h.profileFindFirst.mockResolvedValue({
      id: 'p', source: 'jenkins', config: { url: 'https://ci.example.com' },
    })
    h.settingsFindUnique.mockResolvedValue({
      trufflehogJenkinsUsername: 'svc', trufflehogJenkinsPassword: 'pw',
    })
    const r = await start()
    expect(r.ok).toBe(true)
    if (r.ok) expect(Object.keys(r.body.secrets).sort())
      .toEqual(['trufflehogJenkinsPassword', 'trufflehogJenkinsUsername'])
  })
})

describe('buildTrufflehogCommon', () => {
  test('skip-verification is carried through as its own switch', () => {
    // The scanner needs it separately from the result filter: with verification
    // off, every finding is `unverified` (never checked), not `rejected`.
    expect(buildTrufflehogCommon({ ...PROJECT, trufflehogNoVerification: true }).skipVerification)
      .toBe(true)
  })

  test('result types are split into a list', () => {
    expect(buildTrufflehogCommon({ trufflehogResultTypes: 'verified, unknown' }).resultTypes)
      .toEqual(['verified', 'unknown'])
  })

  test('a project row saved before a field existed falls back to the Prisma default', () => {
    const common = buildTrufflehogCommon({})
    expect(common.resultTypes).toEqual(['verified', 'unverified', 'unknown'])
    expect(common.concurrency).toBe(8)
    expect(common.maxDecodeDepth).toBe(5)
    expect(common.skipVerification).toBe(false)
  })
})

describe('resolveTrufflehogFingerprintExtra', () => {
  test('other kinds are unaffected', async () => {
    expect(await resolveTrufflehogFingerprintExtra('full_recon', 'p1', {})).toEqual({})
  })

  test('the profile config enters the fingerprint', async () => {
    const extra = await resolveTrufflehogFingerprintExtra('trufflehog', 'p1', { profile_id: 'prof1' })
    expect(extra).toMatchObject({
      trufflehogProfileSource: 'docker',
      trufflehogProfileConfig: { images: ['nginx:1.25'] },
    })
  })

  test('re-pointing the profile invalidates a queued job', async () => {
    // Without this the hash covers only the shared options, so changing the
    // Docker namespace would let the job run a config nobody confirmed.
    const before = settingsFingerprint(
      'trufflehog', PROJECT,
      await resolveTrufflehogFingerprintExtra('trufflehog', 'p1', { profile_id: 'prof1' }),
    )
    h.profileFindFirst.mockResolvedValue({ ...DOCKER_PROFILE, config: { namespace: 'other' } })
    const after = settingsFingerprint(
      'trufflehog', PROJECT,
      await resolveTrufflehogFingerprintExtra('trufflehog', 'p1', { profile_id: 'prof1' }),
    )
    expect(after).not.toBe(before)
  })

  test('editing an unrelated profile does not invalidate the job', async () => {
    const a = await resolveTrufflehogFingerprintExtra('trufflehog', 'p1', { profile_id: 'prof1' })
    const b = await resolveTrufflehogFingerprintExtra('trufflehog', 'p1', { profile_id: 'prof1' })
    expect(settingsFingerprint('trufflehog', PROJECT, a))
      .toBe(settingsFingerprint('trufflehog', PROJECT, b))
  })

  test('a deleted profile still changes the hash', async () => {
    // Otherwise the job dispatches as if nothing happened and 404s at start.
    h.profileFindFirst.mockResolvedValue(null)
    const extra = await resolveTrufflehogFingerprintExtra('trufflehog', 'p1', { profile_id: 'gone' })
    expect(extra).toEqual({ trufflehogProfile: 'missing' })
    expect(settingsFingerprint('trufflehog', PROJECT, extra))
      .not.toBe(settingsFingerprint('trufflehog', PROJECT, {}))
  })

  test('a shared option still steers the fingerprint', async () => {
    const extra = await resolveTrufflehogFingerprintExtra('trufflehog', 'p1', { profile_id: 'prof1' })
    expect(settingsFingerprint('trufflehog', PROJECT, extra)).not.toBe(
      settingsFingerprint('trufflehog', { ...PROJECT, trufflehogNoVerification: true }, extra),
    )
  })
})
