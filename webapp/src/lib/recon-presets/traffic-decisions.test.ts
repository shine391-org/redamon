/** @vitest-environment node */
/**
 * Every built-in recon preset DECIDES each tool that sends traffic, instead of
 * inheriting the column default by accident (drift-map #11).
 *
 * Applying a preset resets every field it does not name to its default
 * (applyPresetSettings), so a `traffic: active` toggle whose default is ON runs
 * under every preset that leaves it out, and flipping one default changes what
 * every such preset does without touching a preset file. Two rules, both read
 * from the registry, so a new tool or a flipped default is covered without
 * editing this file:
 *
 *   (a) a preset that leaves a default-ON active toggle unnamed;
 *   (b) a passive or stealth preset that ends up with any active toggle on.
 *
 * Each such (preset, field) pair must be listed in traffic-decisions.allowlist.json
 * with its reason, and every listed pair must still be one: deciding a pair (by
 * naming the field in the preset) means deleting it there.
 *
 * Passive or stealth is read from the preset itself: `stealthMode: true` (the
 * runtime's own stealth switch), or a name or short description that promises
 * no traffic to the target ("Passive Only", "Zero packets to target", "No active
 * scanning"). The outcome is the value the scan runs with: the applied preset,
 * then the registry's stealth profile when stealth mode is on, because
 * apply_stealth_overrides (recon/project_settings.py) forces those values.
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect } from 'vitest'
import { RECON_PRESETS, type ReconPreset } from './index'
import {
  applyPresetSettings,
  defaultFor,
  KEPT_WHEN_ABSENT,
  PRESET_FIELD_KEYS,
} from '../project-preset-utils'
import { field, fieldsWhere } from '../reconSettings/registry'
import allowlist from './traffic-decisions.allowlist.json'

type Decision = { field: string; reason: string; presets: string[] }

const PENDING = allowlist.pending
const DECISIONS: Decision[] = allowlist.decisions

const PASSIVE_PROMISE = /\bpassive only\b|\bzero packets to target\b|\bno active scanning\b/i

/**
 * The toggles a preset has to decide. A toggle whose RoE-safe value is ON (the
 * agent's scope guardrail) is left out: ON is the quiet direction for it, so
 * neither rule can flag a risk there.
 */
const ACTIVE_TOGGLES = fieldsWhere((f, key) =>
  f.traffic === 'active' && f.type === 'boolean' && key.endsWith('Enabled') && f.roe_safe_value !== true,
)
const RESET_WHEN_ABSENT = new Set(PRESET_FIELD_KEYS.filter(k => !KEPT_WHEN_ABSENT.has(k)))

const paramsOf = (p: ReconPreset) => p.parameters as Record<string, unknown>
const names = (p: ReconPreset, key: string) => Object.prototype.hasOwnProperty.call(paramsOf(p), key)

function runsWith(p: ReconPreset): Record<string, unknown> {
  const applied = applyPresetSettings({}, paramsOf(p), {})
  if (applied.stealthMode !== true) return applied
  for (const f of ACTIVE_TOGGLES) {
    if (f.runtime_key && f.stealth && 'set' in f.stealth) applied[f.key] = f.stealth.set
  }
  return applied
}

const isPassiveOrStealth = (p: ReconPreset) =>
  paramsOf(p).stealthMode === true || PASSIVE_PROMISE.test(`${p.name}\n${p.shortDescription}`)

function flaggedPairs(): Map<string, string[]> {
  const out = new Map<string, string[]>()
  for (const p of RECON_PRESETS) {
    const run = runsWith(p)
    const passive = isPassiveOrStealth(p)
    for (const f of ACTIVE_TOGGLES) {
      if (run[f.key] !== true) continue
      const rules: string[] = []
      const d = defaultFor(f.key, {})
      if (!names(p, f.key) && RESET_WHEN_ABSENT.has(f.key) && d.found && d.value === true) rules.push('a')
      if (passive) rules.push('b')
      if (rules.length) out.set(`${p.id} / ${f.key}`, rules)
    }
  }
  return out
}

function allowlistedPairs(): Map<string, string> {
  const out = new Map<string, string>()
  for (const d of DECISIONS) {
    for (const id of d.presets) out.set(`${id} / ${d.field}`, d.reason)
  }
  return out
}

const presetSource = (id: string) =>
  readFileSync(path.join(__dirname, 'presets', `${id}.ts`), 'utf8')

const QUOTED = /^(description|comment): "(.+)"$/s

describe('recon preset traffic decisions (drift-map #11)', () => {
  test('the rules have something to check', () => {
    expect(ACTIVE_TOGGLES.length).toBeGreaterThan(30)
    expect(ACTIVE_TOGGLES.map(f => f.key)).toContain('tlsxEnabled')
    expect(flaggedPairs().size).toBeGreaterThan(0)
  })

  test('passive and stealth presets are recognised from their own data', () => {
    const ids = RECON_PRESETS.filter(isPassiveOrStealth).map(p => p.id)
    expect(ids).toEqual(expect.arrayContaining(['full-passive-scan', 'osint-investigator', 'stealth-recon']))
    for (const p of RECON_PRESETS) {
      if (/passive|stealth/i.test(`${p.id} ${p.name}`)) expect(ids, p.id).toContain(p.id)
    }
  })

  test('every flagged (preset, field) pair is decided in the allowlist', () => {
    const listed = allowlistedPairs()
    const undecided = [...flaggedPairs()]
      .filter(([pair]) => !listed.has(pair))
      .map(([pair, rules]) => `${pair} (rule ${rules.join('+')})`)
    expect(
      undecided,
      'name these fields in the preset, or add the pair to traffic-decisions.allowlist.json with a reason',
    ).toEqual([])
  })

  test('every allowlisted pair is still flagged (a decided pair leaves the list)', () => {
    const flagged = flaggedPairs()
    const stale = [...allowlistedPairs().keys()].filter(pair => !flagged.has(pair))
    expect(stale).toEqual([])
  })

  test('the allowlist names real presets and active toggles, each pair once', () => {
    const presetIds = new Set(RECON_PRESETS.map(p => p.id))
    const toggles = new Set(ACTIVE_TOGGLES.map(f => f.key))
    const seen = new Set<string>()
    const problems: string[] = []
    for (const d of DECISIONS) {
      if (!toggles.has(d.field)) problems.push(`${d.field}: not a traffic:active *Enabled toggle`)
      for (const id of d.presets) {
        if (!presetIds.has(id)) problems.push(`${id}: no such preset`)
        const pair = `${id} / ${d.field}`
        if (seen.has(pair)) problems.push(`${pair}: listed twice`)
        seen.add(pair)
      }
    }
    expect(problems).toEqual([])
  })

  test('every reason is checkable: a quote the preset holds, the stealth profile, or pending', () => {
    const byId = new Map(RECON_PRESETS.map(p => [p.id, p]))
    const problems: string[] = []
    for (const d of DECISIONS) {
      if (d.reason === PENDING) continue
      const quoted = QUOTED.exec(d.reason)
      for (const id of d.presets) {
        const p = byId.get(id)
        if (!p) continue
        if (quoted) {
          const [, kind, quote] = quoted
          const text = kind === 'description' ? `${p.shortDescription}\n${p.fullDescription}` : presetSource(id)
          if (!text.includes(quote)) problems.push(`${id} / ${d.field}: ${kind} does not contain "${quote}"`)
        } else if (d.reason.startsWith('stealth profile:')) {
          if (runsWith(p).stealthMode !== true || field(d.field)?.stealth?.set !== true) {
            problems.push(`${id} / ${d.field}: the stealth profile does not force it on here`)
          }
        } else {
          problems.push(`${id} / ${d.field}: unrecognised reason "${d.reason}"`)
        }
      }
    }
    expect(problems).toEqual([])
  })
})
