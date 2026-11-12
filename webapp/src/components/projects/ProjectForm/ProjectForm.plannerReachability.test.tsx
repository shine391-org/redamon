import { beforeEach, afterEach, expect, test, vi } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { WorkflowView } from './WorkflowView/WorkflowView'
import { ProjectForm } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'
import { qualitySettings } from '@/lib/reconSettings/qualitySettings.testFixtures'

// Keep the real form -> workflow -> modal -> section chain. Only the canvas
// renderer/network hooks are replaced; mocking WorkflowView hides reachability bugs.
vi.mock('next/dynamic', () => ({ default: () => WorkflowView }))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }) }))
vi.mock('@xyflow/react', () => ({
  Handle: () => null, Position: {}, BaseEdge: () => null, getBezierPath: () => [], getSmoothStepPath: () => [],
  ReactFlow: ({ children }: { children: ReactNode }) => <div aria-label="Workflow canvas">{children}</div>,
  Controls: () => null, MiniMap: () => null,
}))
vi.mock('@/hooks/useTheme', () => ({ useTheme: () => ({ resolvedTheme: 'dark' }) }))
vi.mock('./WorkflowView/useToolNodeCounts', () => ({ useDataNodeCounts: () => ({ dataNodeCounts: new Map() }) }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'owner' }) }))
vi.mock('@/hooks/useReconStatus', () => ({ default: () => ({ state: null }) }))
vi.mock('@/hooks/useScanControls', () => ({ useScanControls: () => ({ otherScansOpen: false, gvm: {}, githubHunt: {}, trufflehog: { runs: [] }, supplyChain: {} }) }))
vi.mock('@/components/scans/ScanActions', () => ({ ScanActions: () => null }))
vi.mock('@/app/graph/components/OtherScansModal/OtherScansModal', () => ({ OtherScansModal: () => null }))
vi.mock('@/hooks/useMultiPartialReconStatus', () => ({ useMultiPartialReconStatus: () => ({ runs: [], activeRuns: [], refetch: vi.fn() }) }))
vi.mock('@/hooks/useScanStartFailure', () => ({ useScanStartFailure: () => ({ handleStartFailure: vi.fn() }) }))
vi.mock('@/hooks/useDrawerOffsets', () => ({ useDrawerOffsets: () => {} }))
vi.mock('@/hooks/useMultiPartialReconSSE', () => ({ useMultiPartialReconSSE: () => ({ logsMap: {}, phaseMap: {}, clearLogsForRun: vi.fn() }) }))
vi.mock('@/hooks/useDetectedHostIp', () => ({ useDetectedHostIp: () => '' }))

const submit = vi.fn().mockResolvedValue({})
beforeEach(() => {
  submit.mockClear()
  window.history.replaceState({}, '', '/')
  vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(
    url.endsWith('/llm-providers') ? [{ id: 'provider', providerType: 'openai' }]
      : url === '/api/projects/defaults' ? { ...MINIMAL_DEFAULTS } : url.endsWith('/settings') ? {} : []
  ))))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function draw() {
  render(<QueryClientProvider client={new QueryClient()}><ToastProvider><AlertProvider>
    <ProjectForm mode="edit" initialData={{ ...MINIMAL_DEFAULTS, ...qualitySettings, id: 'p1', userId: 'owner',
      name: 'Synthetic fixture', targetDomain: 'fixture.test', nucleiRateLimit: 42,
      plannerMode: 'shadow', plannerManifestEnabled: true, plannerConsumerAiTags: true,
      plannerConsumerTargetSelection: true, plannerConsumerTwoPass: true } as never}
      projectIdFromRoute="p1" onSubmit={submit} onCancel={vi.fn()} />
  </AlertProvider></ToastProvider></QueryClientProvider>)
}

function checkAndEditControls(scope: ReturnType<typeof within>) {
  expect(scope.getByLabelText('Planner mode')).toHaveValue('shadow')
  fireEvent.change(scope.getByLabelText('Planner mode'), { target: { value: 'enforce' } })
  for (const name of ['Enable plan manifest', 'Enable AI tag consumer', 'Enable target-selection consumer', 'Enable two-pass consumer']) {
    expect(scope.getByRole('switch', { name })).toHaveAttribute('aria-checked', 'true')
    fireEvent.click(scope.getByRole('switch', { name }))
  }
  expect(scope.getByLabelText('Nuclei routing mode')).toHaveValue('enforce')
  fireEvent.change(scope.getByLabelText('Nuclei routing mode'), { target: { value: 'shadow' } })
  for (const name of ['Fetch admission', 'Late sources', 'Chunk checkpoint enabled']) {
    expect(scope.getByLabelText(name)).not.toBeChecked()
    fireEvent.click(scope.getByLabelText(name))
  }
  const group = scope.getByLabelText('Checkpoint budget per group')
  expect(group).toHaveAttribute('min', '0'); expect(group).toHaveAttribute('max', '1000000')
  fireEvent.change(group, { target: { value: '17' } })
  expect(scope.getByLabelText('Checkpoint budget per tool')).toHaveValue(1000000)
  fireEvent.change(scope.getByLabelText('Checkpoint budget per tool'), { target: { value: '0' } })
  expect(scope.getByText(/not individual HTTP requests or the entire pipeline/)).toBeVisible()
}

for (const view of ['tabs', 'workflow']) test(`${view}: real form exposes all controls and submits exact values without scanning`, async () => {
  draw()
  await screen.findByRole('button', { name: 'Planner settings' })
  if (view === 'tabs') {
    fireEvent.click(screen.getByTitle('Tab view'))
    fireEvent.click(screen.getByRole('button', { name: 'Planner' }))
    checkAndEditControls(within(document.body))
  } else {
    fireEvent.click(screen.getByRole('button', { name: 'Planner settings' }))
    const dialog = await screen.findByRole('dialog')
    checkAndEditControls(within(dialog))
    expect(within(dialog).queryByRole('button', { name: /run|start scan/i })).toBeNull()
    fireEvent.click(within(dialog).getByRole('button', { name: /close/i }))
  }
  expect(submit).not.toHaveBeenCalled()
  expect(vi.mocked(fetch).mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false)
  fireEvent.click(screen.getByRole('button', { name: 'Update Settings' }))
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(1))
  expect(submit.mock.calls[0][0]).toMatchObject({ plannerMode: 'enforce', plannerManifestEnabled: false,
    plannerConsumerAiTags: false, plannerConsumerTargetSelection: false, plannerConsumerTwoPass: false,
    nucleiRoutingMode: 'shadow', jsReconFetchAdmission: true, arjunLateSources: true, chunkCheckpointEnabled: true,
    checkpointBudgetPerGroup: 17, checkpointBudgetPerTool: 0, nucleiRateLimit: 42 })
})

test('an unrelated save preserves every stored quality setting, including false and zero', async () => {
  draw()
  await screen.findByRole('button', { name: 'Planner settings' })
  fireEvent.click(screen.getByTitle('Tab view'))
  fireEvent.click(screen.getByRole('button', { name: 'Target & Modules' }))
  fireEvent.change(screen.getByPlaceholderText('Project description (optional)'), { target: { value: 'Unrelated edit' } })
  fireEvent.click(screen.getByRole('button', { name: 'Update Settings' }))
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(1))
  expect(submit.mock.calls[0][0]).toMatchObject({ ...qualitySettings, plannerMode: 'shadow', plannerManifestEnabled: true,
    plannerConsumerAiTags: true, plannerConsumerTargetSelection: true, plannerConsumerTwoPass: true, nucleiRateLimit: 42 })
})
