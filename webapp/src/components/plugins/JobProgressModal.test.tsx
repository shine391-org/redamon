/**
 * JobProgressModal follows an async plugin action (design §6.7): it polls the job, shows the
 * plugin badge, the progress message and fields, and elapsed time; Cancel stops it. On
 * success it hands a reviewProposal to the review modal or shows the message; a failure shows
 * why, and a model_required/model_unavailable failure reopens the gate and offers Retry; a
 * timeout and a cancellation say so.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { JobProgressModal } from './JobProgressModal'
import type { FeatureModelGateApi } from '@/components/shared/FeatureModelGate'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const view = (over: Record<string, unknown>) => ({
  jobId: 'job_1',
  pluginId: 'skiller',
  actionId: 'analyze',
  status: 'running',
  progress: null,
  result: null,
  error: null,
  createdAt: '2026-10-10T10:00:00.000Z',
  updatedAt: '2026-10-10T10:00:00.000Z',
  deadline: '2026-10-10T10:10:00.000Z',
  ...over,
})

/** fetch answers the job views in order, repeating the last; cancel POST answers its arg. */
function stubJob(views: Record<string, unknown>[], onCancel?: () => Record<string, unknown>) {
  let i = 0
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') return new Response(JSON.stringify(onCancel ? onCancel() : view({ status: 'cancelled', error: { code: 'cancelled', message: 'Cancelled by the user.' } })), { status: 200 })
      const v = views[Math.min(i, views.length - 1)]
      i++
      return new Response(JSON.stringify(v), { status: 200 })
    }),
  )
}

const job = { jobId: 'job_1', pluginId: 'skiller', displayName: 'Skiller', label: 'Improve skill' }

function gate(model: string | null = 'anthropic/claude'): FeatureModelGateApi & { ensureFeatureModel: ReturnType<typeof vi.fn> } {
  return { ensureFeatureModel: vi.fn(async () => model), fetchWithFeatureModel: vi.fn(), userId: 'u1', savedVersion: 0 } as never
}

function draw(over: Partial<React.ComponentProps<typeof JobProgressModal>> = {}) {
  const props = {
    job,
    onClose: vi.fn(),
    onReviewProposal: vi.fn(),
    pollMs: 5,
    now: () => Date.parse('2026-10-10T10:00:42.000Z'),
    ...over,
  }
  render(<JobProgressModal {...props} />)
  return props
}

describe('while it runs', () => {
  test('shows the plugin badge, the action label, progress message and fields, and elapsed time', async () => {
    stubJob([view({ status: 'running', progress: { message: 'Reading the session', fields: { Skill: 'ssrf', Stage: 'read' } } })])
    draw()
    expect(await screen.findByText('Reading the session')).toBeInTheDocument()
    expect(screen.getByTitle('RedAmon plugin').textContent).toContain('Skiller')
    expect(screen.getByText('Improve skill')).toBeInTheDocument()
    expect(screen.getByText('Skill').nextSibling?.textContent).toBe('ssrf')
    expect(screen.getByText('Stage').nextSibling?.textContent).toBe('read')
    expect(screen.getByText('0:42')).toBeInTheDocument()
  })

  test('shows the moving progress bar while running, gone once terminal', async () => {
    stubJob([view({ status: 'running' }), view({ status: 'succeeded', result: { message: 'Done.' } })])
    draw({ pollMs: 1 })
    expect(await screen.findByRole('progressbar', { name: 'Working' })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('progressbar')).not.toBeInTheDocument())
  })

  test('a "N of M" Stage field renders that many step dots', async () => {
    stubJob([view({ status: 'running', progress: { message: 'Writing the new version', fields: { Stage: '2 of 3' } } })])
    draw()
    await screen.findByText('Writing the new version')
    expect(document.querySelectorAll('[class*="jobStep"]:not([class*="jobSteps"])')).toHaveLength(3)
    expect(document.querySelectorAll('[class*="jobStepActive"]')).toHaveLength(1)
  })

  test('Cancel stops the job and reports it cancelled', async () => {
    stubJob([view({ status: 'running' })])
    draw()
    await screen.findByRole('button', { name: /cancel/i })
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(await screen.findByText(/cancelled/i)).toBeInTheDocument()
    expect((fetch as ReturnType<typeof vi.fn>).mock.calls.some((c) => (c[1] as RequestInit)?.method === 'POST' && String(c[0]).endsWith('/cancel'))).toBe(true)
  })
})

describe('terminal states', () => {
  test('succeeded with a reviewProposal opens the review and closes', async () => {
    stubJob([view({ status: 'running' }), view({ status: 'succeeded', result: { reviewProposal: { extensionPoint: 'skill.text', changeSetId: 'cs_7' } } })])
    const p = draw()
    await waitFor(() => expect(p.onReviewProposal).toHaveBeenCalledWith('cs_7'))
    expect(p.onClose).toHaveBeenCalled()
  })

  test('succeeded with only a message shows it', async () => {
    stubJob([view({ status: 'succeeded', result: { message: 'No improvement found' } })])
    const p = draw()
    expect(await screen.findByText('No improvement found')).toBeInTheDocument()
    expect(p.onReviewProposal).not.toHaveBeenCalled()
  })

  test('a plain failure shows its message and does not offer retry', async () => {
    stubJob([view({ status: 'failed', error: { code: 'plugin_error', message: 'The engine raised' } })])
    draw({ gate: gate(), onRetry: vi.fn() })
    expect(await screen.findByText('The engine raised')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /retry/i })).toBeNull()
  })

  test('a timeout says so', async () => {
    stubJob([view({ status: 'failed', error: { code: 'timeout', message: 'The action did not report a result before its deadline.' } })])
    draw()
    expect(await screen.findByText(/did not report a result before its deadline/i)).toBeInTheDocument()
    expect(screen.getByText(/timed out/i)).toBeInTheDocument()
  })

  test('model_unavailable reopens the gate, then Retry re-runs through the caller', async () => {
    stubJob([view({ status: 'failed', error: { code: 'model_unavailable', message: 'The chosen model is not available.' } })])
    const g = gate()
    const onRetry = vi.fn()
    draw({ gate: g, onRetry })
    const retry = await screen.findByRole('button', { name: /retry/i })
    fireEvent.click(retry)
    await waitFor(() => expect(g.ensureFeatureModel).toHaveBeenCalledWith('plugin:skiller', expect.objectContaining({ force: true, label: 'Skiller' })))
    expect(onRetry).toHaveBeenCalled()
  })

  test('cancelling the reopened gate does not retry', async () => {
    stubJob([view({ status: 'failed', error: { code: 'model_required', message: 'Choose a model.' } })])
    const g = gate(null)
    const onRetry = vi.fn()
    draw({ gate: g, onRetry })
    fireEvent.click(await screen.findByRole('button', { name: /retry/i }))
    await waitFor(() => expect(g.ensureFeatureModel).toHaveBeenCalled())
    expect(onRetry).not.toHaveBeenCalled()
  })

  test('polling stops once the job is terminal', async () => {
    stubJob([view({ status: 'succeeded', result: {} })])
    draw()
    await screen.findByRole('button', { name: /close/i })
    const after = (fetch as ReturnType<typeof vi.fn>).mock.calls.length
    await new Promise((r) => setTimeout(r, 30))
    expect((fetch as ReturnType<typeof vi.fn>).mock.calls.length).toBe(after)
  })
})

describe('a failure says its cause', () => {
  /** fetch answers each GET in turn with these (a Response factory or a thrown error), repeating the last. */
  function stubPolls(answers: (() => Response)[], cancel?: () => Response) {
    let i = 0
    const fn = vi.fn(async (_url: string, init?: RequestInit) => {
      if (init?.method === 'POST') return cancel ? cancel() : new Response('{}', { status: 200 })
      const a = answers[Math.min(i, answers.length - 1)]
      i++
      return a()
    })
    vi.stubGlobal('fetch', fn)
    return fn
  }
  const ok = (v: Record<string, unknown>) => () => new Response(JSON.stringify(view(v)), { status: 200 })
  const blip = () => new Response('<html>502 Bad Gateway</html>', { status: 502 })

  test('a poll that fails is asked again: a blip does not end the window', async () => {
    const fn = stubPolls([blip, blip, ok({ status: 'succeeded', result: { message: 'All done' } })])
    draw({ pollMs: 1 })
    expect(await screen.findByText('All done')).toBeInTheDocument()
    expect(screen.queryByText(/Lost contact/)).toBeNull()
    expect(fn.mock.calls.length).toBe(3)
  })

  test('polls that keep failing give up with the code and status', async () => {
    const fn = stubPolls([blip])
    draw({ pollMs: 1 })
    expect(await screen.findByText('Lost contact with the job (non_json_response · HTTP 502); it may still be running.')).toBeInTheDocument()
    expect(fn.mock.calls.length).toBe(4)
  })

  test('a job that is not there (404) is not asked again', async () => {
    const fn = stubPolls([() => new Response(JSON.stringify({ error: 'Not found', code: 'not_found' }), { status: 404 })])
    draw({ pollMs: 1 })
    expect(await screen.findByText('Lost contact with the job (not_found · HTTP 404); it may still be running.')).toBeInTheDocument()
    expect(fn.mock.calls.length).toBe(1)
  })

  test('a refused cancel says why under the progress, which keeps going', async () => {
    stubPolls([ok({ status: 'running' })], () => new Response(JSON.stringify({ error: 'Cross-origin request refused.', code: 'cross_origin' }), { status: 403 }))
    draw()
    fireEvent.click(await screen.findByRole('button', { name: /cancel/i }))
    expect(await screen.findByText('The job could not be cancelled (cross_origin · HTTP 403); it may still be running.')).toBeInTheDocument()
    expect(screen.getByRole('progressbar', { name: 'Working' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument()
  })

  test('a cancel that gets no answer says so', async () => {
    stubPolls([ok({ status: 'running' })], () => {
      throw new TypeError('Failed to fetch')
    })
    draw()
    fireEvent.click(await screen.findByRole('button', { name: /cancel/i }))
    expect(await screen.findByText('The job could not be cancelled (network_error); it may still be running.')).toBeInTheDocument()
  })

  test("a failed job shows its code beside the message", async () => {
    stubJob([view({ status: 'failed', error: { code: 'plugin_error', message: 'The engine raised' } })])
    draw()
    await screen.findByText('The engine raised')
    expect(screen.getByTestId('job-error-code').textContent).toBe('plugin_error')
  })

  test('a result report the Gateway refused is said as such, not as a timeout', async () => {
    stubJob([view({ status: 'failed', error: { code: 'report_refused:body_too_large', message: 'The plugin finished, but RedAmon refused its result report (body_too_large, HTTP 413).' } })])
    draw()
    expect(await screen.findByText("The plugin's result was refused.")).toBeInTheDocument()
    expect(screen.queryByText(/timed out/i)).toBeNull()
    expect(screen.getByTestId('job-error-code').textContent).toBe('report_refused:body_too_large')
  })
})
