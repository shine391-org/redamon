/**
 * Which models must be called WITHOUT `temperature`.
 *
 * A copy of the agent's rules in agentic/orchestrator_helpers/llm_setup.py
 * (`ANTHROPIC_NO_TEMPERATURE_*`, `OPENAI_NO_TEMPERATURE_PREFIXES`,
 * `OPENAI_TEMPERATURE_EXCEPTIONS` and the two `_*_supports_temperature`
 * functions), because the webapp build cannot import Python. llmTemperature.test.ts
 * reads those constants from the Python source and fails when the copies differ,
 * and llmTemperature.vectors.json is run through both implementations.
 *
 * These lists are the fast path that saves a rejected first request; a provider
 * 400 naming the parameter is still healed by one retry without it.
 */

export const ANTHROPIC_NO_TEMPERATURE_MODELS: ReadonlySet<string> = new Set([
  'claude-opus-4-7',
  'claude-sonnet-4-7',
  'claude-haiku-4-6',
  'claude-opus-4-8',
])

export const ANTHROPIC_NO_TEMPERATURE_PREFIXES: readonly string[] = [
  'claude-opus-4-8',
  'claude-opus-5',
  'claude-sonnet-5',
  'claude-haiku-5',
  'claude-fable-5',
]

export const OPENAI_NO_TEMPERATURE_PREFIXES: readonly string[] = [
  'o1', 'o3', 'o4',
  'gpt-5', 'gpt-6',
]

export const OPENAI_TEMPERATURE_EXCEPTIONS: readonly string[] = ['gpt-5-chat']

export function anthropicSupportsTemperature(modelId: string): boolean {
  if (ANTHROPIC_NO_TEMPERATURE_MODELS.has(modelId)) return false
  return !ANTHROPIC_NO_TEMPERATURE_PREFIXES.some(p => modelId.startsWith(p))
}

export function openaiSupportsTemperature(modelId: string): boolean {
  // Custom/OpenRouter-style ids may carry a vendor prefix ("openai/gpt-6-luna").
  const name = (modelId.split('/').pop() ?? '').toLowerCase()
  if (OPENAI_TEMPERATURE_EXCEPTIONS.some(p => name.startsWith(p))) return true
  return !OPENAI_NO_TEMPERATURE_PREFIXES.some(p => name.startsWith(p))
}

/**
 * Whether a call to a built-in provider (a `claude-*`, bare OpenAI or
 * `<provider>/` model id) carries `temperature`, as `setup_llm` decides it: the
 * Anthropic rule for Anthropic, the OpenAI rule for OpenAI, never for Kimi
 * (Moonshot's reasoning models accept only 1 and there is no per-model signal),
 * always for the rest.
 */
export function builtinSendsTemperature(providerType: string, modelId: string): boolean {
  switch (providerType) {
    case 'anthropic': return anthropicSupportsTemperature(modelId)
    case 'openai': return openaiSupportsTemperature(modelId)
    case 'kimi': return false
    default: return true
  }
}

/**
 * The same decision for a `custom/<id>` provider row, as `setup_llm`'s custom
 * branch takes it from the row's type: the Anthropic rule for an Anthropic row,
 * always for Bedrock, the OpenAI rule for every other (OpenAI-compatible) row.
 */
export function customSendsTemperature(providerType: string, modelId: string): boolean {
  if (providerType === 'anthropic') return anthropicSupportsTemperature(modelId)
  if (providerType === 'bedrock') return true
  return openaiSupportsTemperature(modelId)
}

/** A provider's 400 that blames the `temperature` parameter, from its raw body. */
export function rejectsTemperature(status: number, body: string): boolean {
  return status === 400 && /temperature/i.test(body)
}
