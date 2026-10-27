/**
 * The JS Recon table's Secret rows, built from the graph by the download route.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { jsReconSecretFromRecord } from './jsReconSecret'

function get(values: Record<string, unknown>) {
  return (key: string) => values[key] ?? null
}

describe('jsReconSecretFromRecord: public client keys (plan 05.2)', () => {
  test('a flagged key is info and says so', () => {
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'GCP API Key', severity: 'info', public_client_key: true,
    }))
    expect(row.severity).toBe('info')
    expect(row.public_client_key).toBe(true)
  })

  test('a key written before the flag is judged by its name', () => {
    const row = jsReconSecretFromRecord(get({ id: 's1', name: 'Sentry DSN', severity: 'medium' }))
    expect(row.severity).toBe('info')
    expect(row.public_client_key).toBe(true)
  })

  test('any other secret keeps its severity', () => {
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'Stripe Secret Key', severity: 'critical', public_client_key: false,
    }))
    expect(row.severity).toBe('critical')
    expect(row.public_client_key).toBe(false)
  })
})

describe('jsReconSecretFromRecord: validation', () => {
  test('the stored validation details are kept', () => {
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'GitHub Token Classic', validation_status: 'validated',
      validation_info: JSON.stringify({ status: 'validated', scope: 'repo', info: 'user=x' }),
    }))
    expect(row.validation).toEqual({ status: 'validated', scope: 'repo', info: 'user=x' })
  })

  test('no status at all is unvalidated', () => {
    expect(jsReconSecretFromRecord(get({ id: 's1', name: 'X' })).validation).toEqual({ status: 'unvalidated' })
  })

  test('the stored status wins over the one inside the details', () => {
    // validation_status is what the Red Zone, the mute rules and the board read;
    // the details are the validator's answer as written at scan time.
    const row = jsReconSecretFromRecord(get({
      id: 's1', name: 'Stripe Secret Key', validation_status: 'rejected',
      validation_info: JSON.stringify({ status: 'skipped', info: 'status=401' }),
    }))
    expect(row.validation).toEqual({ status: 'rejected', info: 'status=401' })
  })

  test('unreadable details fall back to the status', () => {
    const row = jsReconSecretFromRecord(get({ id: 's1', name: 'X', validation_status: 'skipped', validation_info: '{not json' }))
    expect(row.validation).toEqual({ status: 'skipped' })
  })
})
