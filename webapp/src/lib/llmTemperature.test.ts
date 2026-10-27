/**
 * The TS copy of the agent's no-temperature rules (drift-map #14).
 *
 * The constants are compared with the ones in
 * agentic/orchestrator_helpers/llm_setup.py, read from its source, so a model
 * family added on one side only fails here. The behaviour is pinned by
 * llmTemperature.vectors.json, which agentic/tests/test_llm_temperature_vectors.py
 * runs through the Python functions too.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import {
  ANTHROPIC_NO_TEMPERATURE_MODELS,
  ANTHROPIC_NO_TEMPERATURE_PREFIXES,
  OPENAI_NO_TEMPERATURE_PREFIXES,
  OPENAI_TEMPERATURE_EXCEPTIONS,
  anthropicSupportsTemperature,
  builtinSendsTemperature,
  customSendsTemperature,
  openaiSupportsTemperature,
  rejectsTemperature,
} from './llmTemperature'
import vectors from './llmTemperature.vectors.json'

const LLM_SETUP_PY = join(__dirname, '../../../agentic/orchestrator_helpers/llm_setup.py')

/** The string members of a Python set or tuple literal assigned to `name`. */
function pythonStrings(src: string, name: string): string[] {
  const m = new RegExp(`^${name}\\s*=\\s*[({]([^)}]*)[)}]`, 'm').exec(src)
  expect(m, `${name} not found in llm_setup.py`).toBeTruthy()
  const body = m![1].replace(/#[^\n]*/g, '')
  return [...body.matchAll(/["']([^"']+)["']/g)].map(x => x[1])
}

describe('the constants equal the agent\'s', () => {
  const available = existsSync(LLM_SETUP_PY)
  const src = available ? readFileSync(LLM_SETUP_PY, 'utf8') : ''

  test.skipIf(!available)('ANTHROPIC_NO_TEMPERATURE_MODELS', () => {
    expect([...ANTHROPIC_NO_TEMPERATURE_MODELS].sort())
      .toEqual(pythonStrings(src, 'ANTHROPIC_NO_TEMPERATURE_MODELS').sort())
  })

  test.skipIf(!available)('ANTHROPIC_NO_TEMPERATURE_PREFIXES', () => {
    expect([...ANTHROPIC_NO_TEMPERATURE_PREFIXES].sort())
      .toEqual(pythonStrings(src, 'ANTHROPIC_NO_TEMPERATURE_PREFIXES').sort())
  })

  test.skipIf(!available)('OPENAI_NO_TEMPERATURE_PREFIXES', () => {
    expect([...OPENAI_NO_TEMPERATURE_PREFIXES].sort())
      .toEqual(pythonStrings(src, 'OPENAI_NO_TEMPERATURE_PREFIXES').sort())
  })

  test.skipIf(!available)('OPENAI_TEMPERATURE_EXCEPTIONS', () => {
    expect([...OPENAI_TEMPERATURE_EXCEPTIONS].sort())
      .toEqual(pythonStrings(src, 'OPENAI_TEMPERATURE_EXCEPTIONS').sort())
  })
})

describe('the shared vectors', () => {
  test('the table is a real set', () => {
    expect(vectors.anthropic.length).toBeGreaterThanOrEqual(10)
    expect(vectors.openai.length).toBeGreaterThanOrEqual(10)
  })

  test.each(vectors.anthropic)('anthropic $model -> $supportsTemperature', ({ model, supportsTemperature }) => {
    expect(anthropicSupportsTemperature(model)).toBe(supportsTemperature)
  })

  test.each(vectors.openai)('openai $model -> $supportsTemperature', ({ model, supportsTemperature }) => {
    expect(openaiSupportsTemperature(model)).toBe(supportsTemperature)
  })
})

describe('which rule a provider gets, as setup_llm picks it', () => {
  test('built-in providers', () => {
    expect(builtinSendsTemperature('anthropic', 'claude-opus-5')).toBe(false)
    expect(builtinSendsTemperature('anthropic', 'claude-opus-4-6')).toBe(true)
    expect(builtinSendsTemperature('openai', 'gpt-5')).toBe(false)
    expect(builtinSendsTemperature('openai', 'gpt-4o')).toBe(true)
    // Moonshot's reasoning models accept only 1, so the agent never sends it.
    expect(builtinSendsTemperature('kimi', 'moonshot-v1-8k')).toBe(false)
    for (const type of ['openrouter', 'deepseek', 'gemini', 'glm', 'qwen', 'xai', 'mistral']) {
      expect(builtinSendsTemperature(type, 'any-model'), type).toBe(true)
    }
  })

  test('custom provider rows', () => {
    expect(customSendsTemperature('anthropic', 'claude-sonnet-5')).toBe(false)
    expect(customSendsTemperature('bedrock', 'o3')).toBe(true)
    expect(customSendsTemperature('openai_compatible', 'openai/gpt-6-luna')).toBe(false)
    expect(customSendsTemperature('openai_compatible', 'llama3.1:8b')).toBe(true)
  })
})

describe('a 400 that blames temperature', () => {
  test('is recognised in the shapes providers send', () => {
    expect(rejectsTemperature(400, '{"type":"error","error":{"type":"invalid_request_error","message":"`temperature` is deprecated for this model."}}')).toBe(true)
    expect(rejectsTemperature(400, '{"error":{"message":"Unsupported value","param":"temperature","code":"unsupported_value"}}')).toBe(true)
    expect(rejectsTemperature(400, 'invalid temperature: only 1 is allowed for this model')).toBe(true)
  })

  test('another status or another parameter is not', () => {
    expect(rejectsTemperature(401, 'temperature')).toBe(false)
    expect(rejectsTemperature(500, 'temperature')).toBe(false)
    expect(rejectsTemperature(400, '{"error":{"message":"max_tokens is too large"}}')).toBe(false)
  })
})
