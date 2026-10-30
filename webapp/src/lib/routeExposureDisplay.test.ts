import { describe, it, expect } from 'vitest'
import { confirmedInGraph, endpointExposureFields, isRouteExposureFinding, routeExposureDisplayFields } from './routeExposureDisplay'

const lead = {
  source: 'route_exposure', exposure_kind: 'anonymous_access', route_class: 'data_export',
  needs_agent_confirmation: true, http_method: 'GET', path: '/api/v2/reports/export',
  anon_status: 200, authed_status: 200, bodies_match: true, anon_content_class: 'json', anon_size_bucket: '1-10k',
  auth_expected_by: ['siblings_locked', 'openapi'], leak_signals: ['pii_others'], pii_types: ['email', 'phone'],
  pii_record_estimate: 12, sensitive_fields: ['data[].password_hash'], generated_by: 'version',
  variant_of: '/api/v3/reports/export', catch_all_check: 'passed', signature: '', confidence: 0.9,
}

const asMap = (fields: { label: string; value: string }[]) => Object.fromEntries(fields.map(f => [f.label, f.value]))

describe('routeExposureDisplayFields', () => {
  it('labels the codes the node stores', () => {
    const f = asMap(routeExposureDisplayFields(lead, false))
    expect(f['Exposure']).toBe('Answers without a login')
    expect(f['Route class']).toBe('Data export')
    expect(f['Route']).toBe('GET /api/v2/reports/export')
    expect(f['Answers']).toBe('anonymous 200 · logged in 200')
    expect(f['Same page logged in']).toBe('yes')
    expect(f['Anonymous body']).toBe('json, 1-10k')
    expect(f['Login expected because']).toBe('neighbouring routes need a login; the OpenAPI spec declares security')
    expect(f['Leaks']).toBe("other people's personal data (3 or more)")
    expect(f['Personal data']).toBe('email, phone (up to 12 distinct values)')
    expect(f['Sensitive fields']).toBe('data[].password_hash')
    expect(f['Found by']).toBe('older-version guess of /api/v3/reports/export')
    expect(f['Catch-all check']).toMatch(/^passed/)
    expect(f['Confidence']).toBe('90%')
  })

  it('says where the lead stands with the agent', () => {
    expect(asMap(routeExposureDisplayFields(lead, false))['Status']).toMatch(/^Lead: waiting for the agent/)
    expect(asMap(routeExposureDisplayFields(lead, true))['Status']).toBe('Confirmed by the agent')
    expect(asMap(routeExposureDisplayFields(lead))['Status']).toMatch(/^Lead: the agent confirms it/)
    const finding = { source: 'route_exposure', exposure_kind: 'env_file', needs_agent_confirmation: false,
      signature: 'env_lines', confidence: 0.95 }
    const f = asMap(routeExposureDisplayFields(finding, false))
    expect(f['Status']).toBe('Signature finding: proven by recon')
    expect(f['Exposure']).toBe('Exposed .env file')
    expect(f['Signature']).toBe('env_lines')
  })

  it('drops what the node does not carry, and says when no session covered the host', () => {
    const f = asMap(routeExposureDisplayFields({ exposure_kind: 'anonymous_access', anon_status: 200,
      catch_all_check: 'n/a', signature: '', auth_expected_by: [] }))
    expect(f['Answers']).toBe('anonymous 200 · no login session covered this host')
    for (const absent of ['Catch-all check', 'Signature', 'Login expected because', 'Status', 'Confidence']) {
      expect(f[absent]).toBeUndefined()
    }
  })

  it('keeps an unknown code readable rather than dropping it', () => {
    const f = asMap(routeExposureDisplayFields({ exposure_kind: 'new_kind', auth_expected_by: ['new_reason'] }))
    expect(f['Exposure']).toBe('new_kind')
    expect(f['Login expected because']).toBe('new_reason')
  })

  it('says one value, not one values', () => {
    expect(asMap(routeExposureDisplayFields({ pii_types: ['email'], pii_record_estimate: 1 }))['Personal data'])
      .toBe('email (up to 1 distinct value)')
  })

  it('reads a Neo4j integer', () => {
    expect(asMap(routeExposureDisplayFields({ anon_status: { low: 200, high: 0 } }))['Answers'])
      .toBe('anonymous 200 · no login session covered this host')
  })
})

describe('the other helpers', () => {
  it('only a route exposure Vulnerability is one', () => {
    expect(isRouteExposureFinding('Vulnerability', { source: 'route_exposure' })).toBe(true)
    expect(isRouteExposureFinding('Vulnerability', { source: 'nuclei' })).toBe(false)
    expect(isRouteExposureFinding('Endpoint', { source: 'route_exposure' })).toBe(false)
  })

  it('a CONFIRMS edge into the node counts, whether its ends are ids or nodes', () => {
    expect(confirmedInGraph('7', [{ source: '9', target: '7', type: 'CONFIRMS' }])).toBe(true)
    expect(confirmedInGraph('7', [{ source: { id: '9' }, target: { id: '7' }, type: 'CONFIRMS' }])).toBe(true)
    expect(confirmedInGraph('7', [{ source: '7', target: '9', type: 'CONFIRMS' }])).toBe(false)
    expect(confirmedInGraph('7', [{ source: '9', target: '7', type: 'HAS_VULNERABILITY' }])).toBe(false)
    expect(confirmedInGraph('7', undefined)).toBe(false)
  })

  it('an Endpoint shows its anonymous answer and the generator that created it', () => {
    expect(asMap(endpointExposureFields({ anon_status: 200, status_code: 401 }))['Anonymous answer'])
      .toBe("200 (recon's probe saw 401)")
    expect(asMap(endpointExposureFields({ anon_status: 200, status_code: 200 }))['Anonymous answer']).toBe('200')
    expect(asMap(endpointExposureFields({ source: 'route_exposure', generated_by: 'sibling', anon_status: 200 }))['Found by'])
      .toBe('route exposure scan: neighbouring-route guess')
    expect(endpointExposureFields({ source: 'katana', status_code: 200 })).toEqual([])
  })
})
