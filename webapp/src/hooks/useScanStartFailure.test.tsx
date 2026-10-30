/**
 * Scan Queue - useScanStartFailure (Phase 3). Permanent failures show a single
 * error; temporary ones offer Cancel / Add to queue and enqueue on confirm; an
 * ai_attack with an inline api_key is Cancel-only.
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { renderHook } from '@testing-library/react'

const h = vi.hoisted(() => ({
  confirm: vi.fn(),
  alertError: vi.fn(),
  alert: vi.fn(),
}))

vi.mock('@/components/ui/AlertModal/AlertModal', () => ({
  useAlertModal: () => ({ confirm: h.confirm, alertError: h.alertError, alert: h.alert }),
}))

import { useScanStartFailure } from './useScanStartFailure'

beforeEach(() => {
  vi.clearAllMocks()
  h.confirm.mockResolvedValue(false)
  h.alertError.mockResolvedValue(undefined)
  h.alert.mockResolvedValue(undefined)
  global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: 'jq1' }) }) as unknown as typeof fetch
})

function hook(projectId: string | null = 'p1') {
  return renderHook(() => useScanStartFailure(projectId)).result.current
}

test('a permanent failure shows a single error, no confirm', async () => {
  const out = await hook().handleStartFailure('full_recon', { message: 'bad config', status: 400 })
  expect(out).toBe('shown')
  expect(h.confirm).not.toHaveBeenCalled()
  expect(h.alertError).toHaveBeenCalled()
})

test('a permanent failure names its code and status, so a report carries the cause', async () => {
  await hook().handleStartFailure('gvm', { message: 'Failed to start GVM scan', status: 503, code: 'orchestrator_unreachable' })
  expect(h.alertError).toHaveBeenCalledWith('Failed to start GVM scan (orchestrator_unreachable · HTTP 503)', 'Could not start scan')
})

test('a start that got no answer says so', async () => {
  await hook().handleStartFailure('full_recon', { message: 'Failed to start recon', status: 0, code: 'network_error' })
  expect(h.alertError).toHaveBeenCalledWith('Failed to start recon (network_error)', 'Could not start scan')
})

test('a permanent orchestrator code is never offered the queue', async () => {
  await hook().handleStartFailure('gvm', { message: 'spawn failed', status: 503, code: 'spawn_failed' })
  expect(h.confirm).not.toHaveBeenCalled()
})

test('a temporary failure offers the queue and enqueues on confirm', async () => {
  h.confirm.mockResolvedValue(true)
  const out = await hook().handleStartFailure('full_recon', { message: 'no mem', status: 429, limit: { limitType: 'ram' } }, { mode: 'new' })
  expect(out).toBe('queued')
  expect(h.confirm).toHaveBeenCalledWith(expect.anything(), 'Not enough memory', { confirmLabel: 'Add to queue', cancelLabel: 'Cancel' })
  expect(global.fetch).toHaveBeenCalledWith('/api/projects/p1/queue', expect.objectContaining({ method: 'POST' }))
})

test('a temporary failure that the operator cancels does not enqueue', async () => {
  h.confirm.mockResolvedValue(false)
  const out = await hook().handleStartFailure('gvm', { message: 'busy', status: 409 })
  expect(out).toBe('cancelled')
  expect(global.fetch).not.toHaveBeenCalled()
})

test('ai_attack with an inline api_key is Cancel-only (never queued)', async () => {
  const out = await hook().handleStartFailure('ai_attack', { message: 'no mem', status: 429, limit: { limitType: 'ram' } }, { api_key: 'sk-1' })
  expect(out).toBe('shown')
  expect(h.confirm).not.toHaveBeenCalled()
  expect(h.alertError).toHaveBeenCalled()
})

test('an enqueue failure surfaces an error', async () => {
  h.confirm.mockResolvedValue(true)
  global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 500, json: async () => ({ error: 'nope', code: 'P2024' }) }) as unknown as typeof fetch
  const out = await hook().handleStartFailure('full_recon', { message: 'no mem', status: 429, limit: { limitType: 'ram' } })
  expect(out).toBe('shown')
  expect(h.alertError).toHaveBeenCalledWith('nope (P2024 · HTTP 500)')
})

test('an enqueue that got no answer says so', async () => {
  h.confirm.mockResolvedValue(true)
  global.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch')) as unknown as typeof fetch
  await hook().handleStartFailure('full_recon', { message: 'no mem', status: 429, limit: { limitType: 'ram' } })
  expect(h.alertError).toHaveBeenCalledWith('Could not add this scan to the queue. (network_error)')
})
