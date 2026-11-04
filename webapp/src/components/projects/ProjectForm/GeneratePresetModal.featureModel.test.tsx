/**
 * The AI preset generator runs on the user's saved "Recon preset generator"
 * model. The route ignores a model in the body, so none is sent; the gate
 * opens before Generate when none is saved; a non-gate code is shown as its
 * message.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { GATE_USER, jsonResponse, pickInGate, stubGateFetch } from '@/components/shared/featureModelGate.testUtils'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { GeneratePresetModal } from './GeneratePresetModal'

const GENERATE_URL = '/api/presets/generate'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderModal() {
  render(
    <ToastProvider>
      <FeatureModelGateProvider>
        <GeneratePresetModal isOpen onClose={vi.fn()} onSaved={vi.fn()} userId={GATE_USER} />
      </FeatureModelGateProvider>
    </ToastProvider>,
  )
}

function generate(text: string) {
  fireEvent.change(screen.getByRole('textbox'), { target: { value: text } })
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
}

describe('Generate preset', () => {
  test('no saved model: the gate opens first; the request carries the prompt and no model', async () => {
    const stub = stubGateFetch({}, () => jsonResponse(200, { parameters: { naabuEnabled: true } }))
    renderModal()
    generate('fast passive OSINT')
    await pickInGate('Claude Opus 4.6')
    expect(await screen.findByText('Review Generated Preset')).toBeInTheDocument()
    const calls = stub.calls(GENERATE_URL, 'POST')
    expect(calls).toHaveLength(1)
    expect(JSON.parse(calls[0][1]!.body as string)).toEqual({ prompt: 'fast passive OSINT' })
    expect(stub.saved).toEqual({ preset_generator: 'claude-opus-4-6' })
  })

  test('the badge shows the saved model with a Change link', async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' }, () => jsonResponse(404, {}))
    renderModal()
    expect(await screen.findByText('claude-haiku-4-5')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change the Recon preset generator model' })).toHaveTextContent('Change')
  })

  test('a non-gate code is shown as its message and never opens the gate', async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' },
      () => jsonResponse(504, { error: 'x', code: 'agent_timeout', featureId: 'preset_generator' }))
    renderModal()
    generate('fast passive OSINT')
    expect(await screen.findByText('The model took too long, try again')).toBeInTheDocument()
    await waitFor(() => expect(screen.getAllByRole('dialog')).toHaveLength(1))
  })
})

describe('Generate preset: failures say why', () => {
  test("a proxy's HTML 504 is shown with its status, not as a network error", async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' }, () => new Response('<html>504 Gateway Time-out</html>', { status: 504 }))
    renderModal()
    generate('fast passive OSINT')
    expect(await screen.findByText('Failed to generate preset (non_json_response · HTTP 504)')).toBeInTheDocument()
    expect(screen.queryByText(/Network error/)).toBeNull()
  })

  test("a provider refusal shows its error type and the provider's status", async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' }, () => jsonResponse(502, {
      error: 'The model provider answered 429. Try again in a moment.', code: 'insufficient_quota', upstreamStatus: 429,
    }))
    renderModal()
    generate('fast passive OSINT')
    expect(await screen.findByText(
      'The model provider answered 429. Try again in a moment. (insufficient_quota · HTTP 502 · upstream HTTP 429)',
    )).toBeInTheDocument()
  })

  test('an unreachable custom base URL names the errno', async () => {
    stubGateFetch({ preset_generator: 'custom/p1' }, () => jsonResponse(502, {
      error: 'Failed to generate preset. The details are in the webapp log.', code: 'DEPTH_ZERO_SELF_SIGNED_CERT',
    }))
    renderModal()
    generate('fast passive OSINT')
    expect(await screen.findByText(
      'Failed to generate preset. The details are in the webapp log. (DEPTH_ZERO_SELF_SIGNED_CERT · HTTP 502)',
    )).toBeInTheDocument()
  })

  test('the field errors of an invalid preset are still listed', async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' }, () => jsonResponse(422, {
      error: 'Generated preset has invalid fields', details: ['naabuTopPorts: Expected number'],
    }))
    renderModal()
    generate('fast passive OSINT')
    expect(await screen.findByText('Generated preset has invalid fields (HTTP 422)')).toBeInTheDocument()
    expect(screen.getByText('naabuTopPorts: Expected number')).toBeInTheDocument()
  })

  test('no answer at all keeps the network wording and adds network_error', async () => {
    stubGateFetch({ preset_generator: 'claude-haiku-4-5' }, () => { throw new TypeError('Failed to fetch') })
    renderModal()
    generate('fast passive OSINT')
    expect(await screen.findByText('Network error. Check your connection and try again. (network_error)')).toBeInTheDocument()
  })
})
