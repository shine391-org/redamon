/**
 * Where a plugin-platform failure reaches the person, it carries its cause: the code and HTTP
 * status (and the runner's or the agent's status) the server answered, so a screenshot is
 * enough to tell a database timeout from a refused origin or a stopped runner. A failure
 * that may still finish is not called refused, and one that took effect is not called failed.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { operationFailure } from '@/app/plugins/PluginsPageClient'
import { PluginApiError, pluginPost } from '@/hooks/usePlugins'
import type { CatalogView } from '@/lib/plugins/pageModel'
import { CatalogStatus } from './CatalogStatus'
import { PluginDetailsDrawer } from './PluginDetailsDrawer'
import { RunnerStatusBanner } from './RunnerStatusBanner'
import { UninstallDialog } from './UninstallDialog'
import { OverrideApiError, approveChangeSet, resetSkill } from './review/overridesClient'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const withQuery = (ui: React.ReactNode) =>
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>)

describe('lifecycle calls (Install, Update, Enable, Uninstall, ...)', () => {
  test('a refusal keeps its code, status and the install checks’ details', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(422, {
      error: 'The plugin does not match the platform schemas.',
      code: 'manifest_invalid',
      details: ['/actions/0/timeoutSeconds: must be <= 900', '/permissions/1: unknown permission'],
    })))
    const err = (await pluginPost('/api/plugins/echo/install', {}).catch((e) => e)) as PluginApiError
    expect(err).toMatchObject({ code: 'manifest_invalid', status: 422 })
    expect(operationFailure(err)).toEqual({
      title: 'The plugin operation was refused',
      message: 'The plugin does not match the platform schemas. (manifest_invalid · HTTP 422)\n• /actions/0/timeoutSeconds: must be <= 900\n• /permissions/1: unknown permission',
    })
  })

  test('a 500 is a failure, with the safe code', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: 'The plugin operation failed; see the webapp log.', code: 'P2024' })))
    const err = (await pluginPost('/api/plugins/echo/enable', {}).catch((e) => e)) as PluginApiError
    expect(operationFailure(err)).toEqual({ title: 'The plugin operation failed', message: 'The plugin operation failed; see the webapp log. (P2024 · HTTP 500)' })
  })

  test("a proxy's page or no answer: the outcome is unknown, not refused", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>504 Gateway Time-out</html>', { status: 504 })))
    const proxied = (await pluginPost('/api/plugins/echo/update', {}).catch((e) => e)) as PluginApiError
    expect(operationFailure(proxied)).toEqual({
      title: 'The outcome of the plugin operation is unknown',
      message: 'The plugin operation failed (non_json_response · HTTP 504)\nIt may still be running; the page refreshes to show its state.',
    })
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const none = (await pluginPost('/api/plugins/echo/update', {}).catch((e) => e)) as PluginApiError
    expect(none).toMatchObject({ code: 'network_error', status: 0 })
    expect(operationFailure(none).title).toBe('The outcome of the plugin operation is unknown')
  })

  test("an upload over the proxy's limit (a non-JSON 413) is refused, not pending", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>413 Request Entity Too Large</html>', { status: 413 })))
    const err = (await pluginPost('/api/plugins/offline-install', {}).catch((e) => e)) as PluginApiError
    expect(operationFailure(err).title).toBe('The plugin operation was refused')
  })

  test('a failure after the commit says the operation took effect', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(500, {
      error: 'The install of echo 1.0.0 took effect, but a step after it failed (P2024); the page shows its state now. The webapp log has the details.',
      code: 'P2024',
      committed: true,
    })))
    const err = (await pluginPost('/api/plugins/echo/install', {}).catch((e) => e)) as PluginApiError
    expect(operationFailure(err).title).toBe('The plugin operation took effect, with an error')
    expect(operationFailure(err).message).toContain('took effect')
  })
})

describe('the override routes (approve, reject, reset, versions)', () => {
  test('an approval the agent cannot check names the agent status, and keeps every over-limit error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(503, {
      error: 'The agent service answered HTTP 500, so this approval cannot be checked now.',
      code: 'agent_unreachable',
      upstreamStatus: 500,
    })))
    const agent = (await approveChangeSet('cs1', null).catch((e) => e)) as OverrideApiError
    expect(agent.message).toBe('The agent service answered HTTP 500, so this approval cannot be checked now. (agent_unreachable · HTTP 503 · upstream HTTP 500)')

    vi.stubGlobal('fetch', vi.fn(async () => json(422, { error: 'Part tools is over 20000 characters.', code: 'over_limit', errors: ['Part tools is over 20000 characters.', 'The skill is over 60000 characters.'] })))
    const limit = (await approveChangeSet('cs1', null).catch((e) => e)) as OverrideApiError
    expect(limit.details).toEqual(['Part tools is over 20000 characters.', 'The skill is over 60000 characters.'])
  })

  test("Next's empty 500 and no answer are both named", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 500 })))
    expect(((await resetSkill({ group: 'sql_injection', scopeType: 'user' }).catch((e) => e)) as OverrideApiError).message).toBe(
      'The request failed (empty_response · HTTP 500)',
    )
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const none = (await resetSkill({ group: 'sql_injection', scopeType: 'user' }).catch((e) => e)) as OverrideApiError
    expect(none).toBeInstanceOf(OverrideApiError)
    expect(none).toMatchObject({ code: 'network_error', status: 0, message: 'RedAmon did not answer (network_error)' })
  })

  test('a reset that took effect before a later step failed keeps committed in extra', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: 'The skill was reset, but its audit entry could not be written; see the webapp log.', code: 'P2024', committed: true })))
    const err = (await resetSkill({ group: 'sql_injection', scopeType: 'user' }).catch((e) => e)) as OverrideApiError
    expect(err.extra.committed).toBe(true)
  })
})

describe('the runner banner', () => {
  const status = (runner: Record<string, unknown>) => json(200, { platformVersion: '1.1.0', runner })

  test.each<[Record<string, unknown>, string]>([
    [{ reachable: false, error: 'runner_unavailable', reason: 'timeout', proxyCode: 'upstream_timeout' }, 'The plugin runner did not answer in time (upstream_timeout).'],
    [{ reachable: false, error: 'runner_unavailable', reason: 'unreachable' }, 'The plugin runner is not reachable (unreachable).'],
    [{ reachable: false, error: 'runner_unavailable', reason: 'unreachable', proxyCode: 'proxy_busy' }, 'The plugin runner is not reachable (proxy_busy).'],
    [{ reachable: false, error: 'unauthorized', upstreamStatus: 401 }, 'The plugin runner answered unauthorized (HTTP 401).'],
    [{ reachable: false, error: 'runner_not_configured', reason: 'not_configured' }, 'The runner key is not configured (PLUGIN_RUNNER_KEY).'],
  ])('%j: %s', async (runner, text) => {
    vi.stubGlobal('fetch', vi.fn(async () => status(runner)))
    withQuery(<RunnerStatusBanner />)
    expect(await screen.findByText(text)).toBeInTheDocument()
  })

  test('a status that cannot be read is said, not hidden as a healthy runner', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: 'The plugin status could not be read; see the webapp log.', code: 'P2024' })))
    withQuery(<RunnerStatusBanner />)
    expect((await screen.findByTestId('runner-banner')).textContent).toContain('The plugin status could not be read; see the webapp log. (P2024 · HTTP 500)')
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 502 })))
    cleanup()
    withQuery(<RunnerStatusBanner />)
    expect((await screen.findByTestId('runner-banner')).textContent).toContain('Runner status unknown (empty_response · HTTP 502)')
  })
})

describe('the catalog banner', () => {
  const base: CatalogView = { state: 'invalid', message: 'The plugin catalog is not a valid catalog for this RedAmon, so it is not used.', official: false, extraKey: false, replayed: false, serial: null }

  test("an admin's view shows the check's sentence and the schema paths, React-escaped", () => {
    render(<CatalogStatus catalog={{ ...base, detail: 'The signed catalog does not match the catalog schema.', details: ['/plugins/0/id: <b>must</b> match'] }} />)
    expect(screen.getByTestId('catalog-detail').textContent).toBe('The signed catalog does not match the catalog schema.')
    expect(screen.getByTestId('catalog-details').textContent).toBe('/plugins/0/id: <b>must</b> match')
    expect(screen.getByTestId('catalog-details').querySelector('b')).toBeNull()
  })

  test('without a detail, only the advice', () => {
    render(<CatalogStatus catalog={base} />)
    expect(screen.queryByTestId('catalog-detail')).toBeNull()
  })
})

describe('the export download', () => {
  function stubExport(res: () => Response) {
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    // jsdom has no object URLs.
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    vi.stubGlobal('fetch', vi.fn(async () => res()))
    return click
  }

  test('uninstall: a refused export is shown and does not unlock the purge', async () => {
    const click = stubExport(() => json(403, { error: 'The export is downloaded from the Plugins page itself.', code: 'cross_site' }))
    render(<UninstallDialog isOpen pluginId="echo" pluginName="Echo" onConfirm={vi.fn()} onCancel={vi.fn()} keptOnly />)
    fireEvent.change(screen.getByRole('textbox', { name: /type echo/i }), { target: { value: 'echo' } })
    fireEvent.click(screen.getByRole('button', { name: /download the export/i }))
    expect(await screen.findByText('The export is downloaded from the Plugins page itself. (cross_site · HTTP 403)')).toBeInTheDocument()
    expect((screen.getByRole('button', { name: 'Delete kept data' }) as HTMLButtonElement).disabled).toBe(true)
    expect(click).not.toHaveBeenCalled()
  })

  test('uninstall: a downloaded export unlocks the purge', async () => {
    const click = stubExport(() => new Response('{"rows":[]}', { status: 200, headers: { 'Content-Disposition': 'attachment; filename="echo-export.json"' } }))
    render(<UninstallDialog isOpen pluginId="echo" pluginName="Echo" onConfirm={vi.fn()} onCancel={vi.fn()} keptOnly />)
    fireEvent.change(screen.getByRole('textbox', { name: /type echo/i }), { target: { value: 'echo' } })
    fireEvent.click(screen.getByRole('button', { name: /download the export/i }))
    await waitFor(() => expect((screen.getByRole('button', { name: 'Delete kept data' }) as HTMLButtonElement).disabled).toBe(false))
    expect(click).toHaveBeenCalledTimes(1)
    expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe('echo-export.json')
  })
})

describe('the details drawer', () => {
  function drawer(answer: (url: string) => Response) {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => answer(url)))
    withQuery(<PluginDetailsDrawer pluginId="echo" isOpen onClose={vi.fn()} onRollback={vi.fn()} />)
  }

  test("details that fail to load say why, a 404 with the server's sentence", async () => {
    drawer((url) => (url === '/api/plugins/echo' ? json(404, { error: 'Plugin echo is not known.', code: 'not_found' }) : json(200, { lines: [] })))
    expect(await screen.findByText('Plugin echo is not known. (not_found · HTTP 404)')).toBeInTheDocument()
  })

  test('a log the webapp refused is not blamed on the runner; no answer is said too', async () => {
    drawer((url) => (url === '/api/plugins/echo' ? json(500, {}) : json(403, { error: 'Only an administrator can manage plugins.', code: 'admin_required' })))
    const line = await screen.findByTestId('plugin-log-unavailable')
    expect(line.textContent).toBe('Only an administrator can manage plugins. (admin_required · HTTP 403)')
    cleanup()
    drawer((url) => {
      if (url.includes('/logs')) throw new TypeError('Failed to fetch')
      return json(500, {})
    })
    expect((await screen.findByTestId('plugin-log-unavailable')).textContent).toBe('The log could not be read (network_error)')
  })

  test('a runner that is down is framed as such, with its code and status', async () => {
    drawer((url) => (url === '/api/plugins/echo' ? json(500, {}) : json(503, { error: 'The plugin runner could not be reached.', code: 'runner_unavailable', reason: 'unreachable' })))
    expect((await screen.findByTestId('plugin-log-unavailable')).textContent).toBe(
      'The plugin runner is unavailable, so its log cannot be read: The plugin runner could not be reached. (runner_unavailable · HTTP 503)',
    )
  })
})
