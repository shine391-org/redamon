/**
 * A model list that fails to load says why (U-2, G-11): the code tells the agent not running
 * (agent_unreachable) from the agent failing (agent_error), and the status is shown with it.
 * Every picker reads the list through the shared fetchModelOptions.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, renderHook, waitFor } from '@testing-library/react'
import { ModelPicker } from './ModelPicker'
import { useModelPicker } from '@/app/graph/components/AIAssistantDrawer/hooks/useModelPicker'
import { ModelPickerModal } from '@/app/graph/components/AIAssistantDrawer/ModelPickerModal'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function stubModels(answer: () => Promise<Response>) {
  const fetchMock = vi.fn(answer)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function openPicker(props: Partial<React.ComponentProps<typeof ModelPicker>> = {}) {
  render(<ModelPicker userId="u1" value="" onChange={vi.fn()} {...props} />)
  await waitFor(() => expect(screen.queryByText('Loading models...')).toBeNull())
  fireEvent.click(document.querySelector('[class*="modelSelectorInput"]') as HTMLElement)
}

describe('ModelPicker', () => {
  test('an agent that is down: the code and status, then the manual input', async () => {
    stubModels(async () => json(503, { error: 'Failed to connect to agent API', code: 'agent_unreachable', cause: 'ECONNREFUSED' }))
    await openPicker()
    expect(await screen.findByText('Failed to load models (agent_unreachable · HTTP 503). Type a model ID manually:')).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/claude-opus-4-6/)).toBeInTheDocument()
  })

  test("an agent that failed: its status too; without the manual input the line still says why", async () => {
    stubModels(async () => json(503, { error: 'Failed to fetch models from agent API', code: 'agent_error', upstreamStatus: 500 }))
    await openPicker({ hideManualFallback: true })
    expect(await screen.findByText('Failed to load models (agent_error · HTTP 503 · upstream HTTP 500).')).toBeInTheDocument()
  })

  test('no answer at all is network_error', async () => {
    stubModels(async () => { throw new TypeError('Failed to fetch') })
    await openPicker()
    expect(await screen.findByText('Failed to load models (network_error). Type a model ID manually:')).toBeInTheDocument()
  })

  test('the request is the shared one: POST with the userId, no store', async () => {
    const fetchMock = stubModels(async () => json(200, { Anthropic: [] }))
    await openPicker()
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/models')
    expect(init).toMatchObject({ method: 'POST', cache: 'no-store', body: JSON.stringify({ userId: 'u1' }) })
  })
})

describe('the chat drawer model modal', () => {
  test('useModelPicker keeps the cause, and the modal shows it', async () => {
    stubModels(async () => json(504, { error: 'Failed to connect to agent API', code: 'agent_timeout' }))
    const { result } = renderHook(() => useModelPicker('u1'))
    result.current.setShowModelModal(true)
    await waitFor(() => expect(result.current.modelsError).toBe('Failed to load models (agent_timeout · HTTP 504)'))
    render(
      <ModelPickerModal
        showModelModal
        setShowModelModal={vi.fn()}
        modelSearch=""
        setModelSearch={vi.fn()}
        modelSearchRef={{ current: null }}
        modelsLoading={false}
        modelsError={result.current.modelsError}
        filteredModels={{}}
        handleSelectModel={vi.fn()}
      />,
    )
    expect(screen.getByText('Failed to load models (agent_timeout · HTTP 504). Type a model ID manually:')).toBeInTheDocument()
  })

  test('a plain true still reads as before', () => {
    render(
      <ModelPickerModal
        showModelModal
        setShowModelModal={vi.fn()}
        modelSearch=""
        setModelSearch={vi.fn()}
        modelSearchRef={{ current: null }}
        modelsLoading={false}
        modelsError
        filteredModels={{}}
        handleSelectModel={vi.fn()}
      />,
    )
    expect(screen.getByText('Failed to load models. Type a model ID manually:')).toBeInTheDocument()
  })
})
