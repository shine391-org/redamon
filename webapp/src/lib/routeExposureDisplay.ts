/**
 * How a route exposure finding is LABELLED in the drawer and the Node Inspector.
 *
 * The node stores codes (`auth_expected_by: ["siblings_locked"]`,
 * `leak_signals: ["pii_others"]`, `generated_by: "version"`) because the agent's
 * Cypher and the mute rules match on them. Shown raw, they leave the operator
 * guessing why recon thought a route should need a login and what it leaked.
 * Declared in graph_db/schema_sections.md ("Route exposure properties").
 */

export interface RouteExposureDisplayField {
  label: string
  value: string
}

const KIND: Record<string, string> = {
  anonymous_access: 'Answers without a login',
  sensitive_data: 'Sensitive data in the answer',
  cors_misconfig: 'Credentialed CORS origin reflection',
  auth_cacheable: 'Logged-in answer is cacheable',
  vcs_exposure: 'Exposed version control (.git)',
  env_file: 'Exposed .env file',
  config_file: 'Exposed config file',
  backup_file: 'Exposed backup file',
  debug_console: 'Debug console',
  debug_endpoint: 'Debug endpoint',
  debug_page: 'Debug error page',
  route_catalog: 'Route catalog',
  secret_in_response: 'Secret in the answer',
}

const ROUTE_CLASS: Record<string, string> = {
  internal_api: 'Internal API',
  debug_management: 'Debug / management',
  admin_function: 'Admin function',
  data_export: 'Data export',
  old_version: 'Older API version',
  uploaded_content: 'Uploaded content',
  client_gated: 'Gated only in the browser',
  unknown: 'Unclassified',
}

const AUTH_EXPECTED: Record<string, string> = {
  openapi: 'the OpenAPI spec declares security',
  openapi_tag: 'an OpenAPI tag marks it private',
  declared_only: 'only the spec lists it',
  seen_denied: 'an earlier scan was denied',
  path_word: 'its path names an admin or internal area',
  host_word: 'its host name reads internal',
  siblings_locked: 'neighbouring routes need a login',
  version_locked: 'a newer version needs a login',
  vary_auth: 'the answer varies on Authorization',
}

const LEAK: Record<string, string> = {
  pii: 'personal data',
  pii_others: "other people's personal data (3 or more)",
  sensitive_fields: 'sensitive field names',
  secret: 'a secret',
}

const GENERATED_BY: Record<string, string> = {
  found: 'already known to recon',
  seed: 'common-path list',
  vcs: 'version-control guess',
  backup: 'backup-name guess',
  version: 'older-version guess',
  sibling: 'neighbouring-route guess',
  framework: 'framework default path',
  catalog: 'route catalog',
  cross_host: 'same route on another host',
}

const CATCH_ALL: Record<string, string> = {
  passed: 'passed (a made-up path nearby answered differently)',
  failed: 'inconclusive',
}

function list(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string' && v !== '')
  return typeof value === 'string' && value ? [value] : []
}

function num(value: unknown): number | null {
  if (typeof value === 'number') return value
  if (value && typeof value === 'object' && 'low' in value) return (value as { low: number }).low
  return null
}

const labelled = (codes: string[], table: Record<string, string>) =>
  codes.map(c => table[c] ?? c).join('; ')

export function isRouteExposureFinding(type: string | undefined, properties: Record<string, unknown> | undefined): boolean {
  return type === 'Vulnerability' && properties?.source === 'route_exposure'
}

/** Whether a proof-typed ChainFinding already CONFIRMS this node in the loaded graph. */
export function confirmedInGraph(
  nodeId: string,
  links: { source: unknown; target: unknown; type: string }[] | undefined,
): boolean {
  const id = (end: unknown) => (end && typeof end === 'object' ? (end as { id?: string }).id : end)
  return (links ?? []).some(l => l.type === 'CONFIRMS' && id(l.target) === nodeId)
}

/**
 * A route exposure finding's properties as labelled rows, ready to render.
 * Empty fields are dropped. `confirmed` is the caller's reading of the CONFIRMS
 * edge; null when it cannot tell (the edge is not on the node itself).
 */
export function routeExposureDisplayFields(
  properties: Record<string, unknown>,
  confirmed: boolean | null = null,
): RouteExposureDisplayField[] {
  const out: RouteExposureDisplayField[] = []
  const push = (label: string, value: string | null | undefined) => {
    if (value) out.push({ label, value })
  }

  const kind = String(properties.exposure_kind ?? '')
  push('Exposure', KIND[kind] ?? kind)

  if (properties.needs_agent_confirmation === true) {
    push('Status', confirmed === true
      ? 'Confirmed by the agent'
      : confirmed === false
        ? 'Lead: waiting for the agent to confirm it (stays info until then)'
        : 'Lead: the agent confirms it (stays info until then)')
  } else if (properties.needs_agent_confirmation === false) {
    push('Status', 'Signature finding: proven by recon')
  }

  const routeClass = String(properties.route_class ?? '')
  push('Route class', ROUTE_CLASS[routeClass] ?? routeClass)

  const method = String(properties.http_method ?? '')
  const path = String(properties.path ?? '')
  push('Route', path ? `${method ? `${method} ` : ''}${path}` : '')

  const anon = num(properties.anon_status)
  const authed = num(properties.authed_status)
  if (anon != null) {
    push('Answers', authed != null
      ? `anonymous ${anon} · logged in ${authed}`
      : `anonymous ${anon} · no login session covered this host`)
  }
  if (typeof properties.bodies_match === 'boolean') {
    push('Same page logged in', properties.bodies_match ? 'yes' : 'no')
  }
  const content = [properties.anon_content_class, properties.anon_size_bucket].filter(Boolean).join(', ')
  push('Anonymous body', content)

  push('Login expected because', labelled(list(properties.auth_expected_by), AUTH_EXPECTED))
  push('Leaks', labelled(list(properties.leak_signals), LEAK))

  const pii = list(properties.pii_types)
  const records = num(properties.pii_record_estimate)
  push('Personal data', pii.length
    ? `${pii.join(', ')}${records ? ` (up to ${records} distinct value${records === 1 ? '' : 's'})` : ''}`
    : '')
  push('Sensitive fields', list(properties.sensitive_fields).join(', '))
  push('Secret detectors', list(properties.secret_types).join(', '))
  push('Signature', String(properties.signature ?? ''))

  const generated = String(properties.generated_by ?? '')
  const variantOf = String(properties.variant_of ?? '')
  push('Found by', generated
    ? `${GENERATED_BY[generated] ?? generated}${variantOf ? ` of ${variantOf}` : ''}`
    : '')

  const catchAll = String(properties.catch_all_check ?? '')
  push('Catch-all check', catchAll === 'n/a' ? '' : CATCH_ALL[catchAll] ?? catchAll)

  const confidence = num(properties.confidence)
  push('Confidence', confidence != null ? `${Math.round(confidence * 100)}%` : '')
  push('Evidence', String(properties.evidence_snippet ?? ''))

  return out
}

/** An Endpoint the route exposure scan measured: its anonymous answer, and the
 *  generator that found it when the scan created the Endpoint itself. */
export function endpointExposureFields(properties: Record<string, unknown>): RouteExposureDisplayField[] {
  const out: RouteExposureDisplayField[] = []
  const anon = num(properties.anon_status)
  if (anon != null) {
    const seen = num(properties.status_code)
    out.push({
      label: 'Anonymous answer',
      value: seen != null && seen !== anon ? `${anon} (recon's probe saw ${seen})` : String(anon),
    })
  }
  if (properties.source === 'route_exposure') {
    const generated = String(properties.generated_by ?? '')
    out.push({ label: 'Found by', value: `route exposure scan${generated ? `: ${GENERATED_BY[generated] ?? generated}` : ''}` })
  }
  return out
}
