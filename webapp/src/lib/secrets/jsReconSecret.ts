/**
 * One Secret row of the JS Recon table, from the download route's record.
 */
import { isPublicClientKey } from './publicClientKeys'

export interface JsReconSecretRow {
  nodeId: unknown
  id: unknown
  name: unknown
  severity: unknown
  public_client_key: boolean
  redacted_value: unknown
  matched_text: unknown
  category: unknown
  source_url: unknown
  confidence: unknown
  detection_method: unknown
  validation: Record<string, unknown>
  updatedAt: unknown
}

export function jsReconSecretFromRecord(get: (key: string) => unknown): JsReconSecretRow {
  // The node's validation_status is what every other reader (the Red Zone,
  // mute rules, the Priority Board) goes by, so it wins over the copy inside
  // the validator's details.
  const stored = get('validation_status')
  let validation: Record<string, unknown> = { status: stored || 'unvalidated' }
  const info = get('validation_info')
  if (typeof info === 'string' && info) {
    try {
      const parsed = JSON.parse(info)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        validation = { ...parsed, status: stored || parsed.status || 'unvalidated' }
      }
    } catch { /* keep the stored status */ }
  }
  // A node written before `public_client_key` keeps its old severity until
  // JS Recon runs again; its pattern name still says public.
  const publicClientKey = isPublicClientKey(get('public_client_key'), get('name'))
  return {
    nodeId: get('nodeId') ?? null,
    id: get('id'),
    name: get('name'),
    severity: publicClientKey ? 'info' : get('severity'),
    public_client_key: publicClientKey,
    redacted_value: get('redacted_value'),
    matched_text: get('matched_text'),
    category: get('category'),
    source_url: get('source_url'),
    confidence: get('confidence'),
    detection_method: get('detection_method'),
    validation,
    updatedAt: get('updatedAt') ?? null,
  }
}
