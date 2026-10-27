/**
 * Every hand-written server validator accepts exactly its field's registry bound.
 *
 * describe_recon_settings tells an MCP caller the registry bound; the PATCH route
 * enforces these validators. Where the two differed, a caller was told 0-10 and
 * refused for 0 and 6-10 (fireteamPropensity, drift-map #24). Each bound is probed
 * at both ends and one step outside, so the validators are checked by behaviour
 * rather than by reading their source.
 */
import { describe, expect, it } from 'vitest'
import registry from '@/lib/reconSettings/registry.json'
import { FireteamSettingsSchema, validateFireteamSettings } from './fireteamSettings'
import { validateOpenApiSettings } from './openapiSettings'

type Bounds = { min: number; max: number }

const fields = (registry as { fields: Record<string, { bounds?: Bounds }> }).fields

const VALIDATORS: Array<{ name: string; validate: (body: Record<string, unknown>) => string | null; fields: string[] }> = [
  {
    name: 'validateFireteamSettings',
    validate: validateFireteamSettings,
    // every numeric field of the schema, so a field added there is covered here
    fields: Object.entries(FireteamSettingsSchema.shape)
      .filter(([, schema]) => schema.unwrap().type === 'number')
      .map(([field]) => field),
  },
  {
    name: 'validateOpenApiSettings',
    validate: validateOpenApiSettings,
    fields: ['openapiTimeout', 'openapiMaxDocuments'],
  },
]

describe('hand-written validators match the registry bounds', () => {
  for (const { name, validate, fields: names } of VALIDATORS) {
    for (const field of names) {
      it(`${name}: ${field}`, () => {
        const bounds = fields[field]?.bounds
        expect(bounds, `${field} has no registry bound`).toBeDefined()
        const { min, max } = bounds as Bounds
        expect(validate({ [field]: min }), `${field}=${min} (registry min) refused`).toBeNull()
        expect(validate({ [field]: max }), `${field}=${max} (registry max) refused`).toBeNull()
        expect(validate({ [field]: min - 1 }), `${field}=${min - 1} accepted below the registry min`).not.toBeNull()
        expect(validate({ [field]: max + 1 }), `${field}=${max + 1} accepted above the registry max`).not.toBeNull()
      })
    }
  }
})
