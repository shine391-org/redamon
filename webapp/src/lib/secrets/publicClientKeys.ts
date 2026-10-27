/**
 * Keys that are PUBLIC BY DESIGN: a browser key, a publishable key, a DSN, a
 * write-only analytics key. They ship to every browser that loads the page, so
 * the report and Insights list them apart instead of counting them as exposed
 * secrets, and the Red Zone shows them at info.
 *
 * js_recon writes such a Secret at severity info with `public_client_key`.
 * Nodes written before that flag keep their old severity until the next JS
 * Recon run, and GitHub-hunt nodes never carry it, so a reader decides on the
 * flag OR the stored pattern name.
 *
 * Lowercased exact names, equal to score_model.PUBLIC_CLIENT_KEY_TYPES (pinned
 * by publicClientKeys.test.ts), never substrings: "stripe" alone is also a
 * secret key.
 */
export const PUBLIC_CLIENT_KEY_TYPES: readonly string[] = [
  'gcp api key',
  'gcpkey',
  'firebase api key',
  'segment write key',
  'amplitude api key',
  'new relic browser api token',
  'sentry dsn',
  'stripe publishable key',
  'google recaptcha key',
  'mapbox token',
  'algolia app id',
  'algolia search key',
  'intercom app id',
  'pusher key',
  'clerk publishable key',
  'mailgun public key',
  'flutterwave public key',
  'supabase anon key',
  'supabase publishable key',
]

const PUBLIC_SET: ReadonlySet<string> = new Set(PUBLIC_CLIENT_KEY_TYPES)

export function isPublicClientKey(flag: unknown, secretType: unknown): boolean {
  if (flag === true) return true
  return typeof secretType === 'string' && PUBLIC_SET.has(secretType.trim().toLowerCase())
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/
const PUBLIC_LIST = `[${PUBLIC_CLIENT_KEY_TYPES.map(n => `'${n}'`).join(', ')}]`

/** The same test in Cypher, over the node bound to `alias`. Binds no
 *  parameter, so a caller adds it to any query as it is. */
export function publicClientKeyCypher(alias: string): string {
  if (!IDENTIFIER.test(alias)) throw new Error(`not a Cypher identifier: ${alias}`)
  return `(coalesce(${alias}.public_client_key, false) = true ` +
    `OR toLower(coalesce(${alias}.secret_type, '')) IN ${PUBLIC_LIST})`
}
