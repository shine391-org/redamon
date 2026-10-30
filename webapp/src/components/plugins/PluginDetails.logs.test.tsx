/**
 * The admin's details of one plugin (README.PLUGIN_SDK.md §12, D-77, R-12): its last error, the
 * versions on disk, the granted permissions, its data usage against the quotas, its approved
 * skill versions, whether a rollback is possible and why not, an export, and the last 200
 * lines of its log from the runner's ring buffer, with a refresh.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { PluginDetailsDrawer } from './PluginDetailsDrawer'

let detail: unknown
let logs: { status: number; body: unknown }
const calls: string[] = []

function detailOf(over: Record<string, unknown> = {}) {
  return {
    plugin: {
      id: 'echo', displayName: 'Echo', description: 'x', inCatalog: true, state: 'failed',
      installed: { version: '1.1.0', previousVersion: '1.0.0', status: 'failed', enabled: true, dataVersion: 2, grantedPermissions: ['session:read'], installedAt: null, revokedReason: null, operationKind: null, lastError: 'worker_failed: the worker is failed' },
      available: null, update: null, installBlocked: null,
    },
    admin: {
      lastError: 'worker_failed: the worker is failed',
      versionsOnDisk: ['1.0.0', '1.1.0'],
      grantedPermissions: [{ id: 'session:read', title: 'Read chat sessions', consent: '...' }],
      data: { rows: 1234, bytes: 2_621_440, maxRows: 10_000, maxBytes: 52_428_800 },
      activeVersions: 2,
      dormantVersions: 2,
      rollback: { possible: true, migrates: true },
      ...over,
    },
  }
}

beforeEach(() => {
  detail = detailOf()
  logs = { status: 200, body: { lines: ['1.1.0 [runner] worker started: pid 42 uid 20001', '1.1.0 Traceback (most recent call last):'] } }
  calls.length = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    calls.push(url)
    if (url === '/api/plugins/echo') return new Response(JSON.stringify(detail))
    if (url.startsWith('/api/plugins/echo/logs')) return new Response(JSON.stringify(logs.body), { status: logs.status })
    return new Response('{}', { status: 404 })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function show(onRollback = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <PluginDetailsDrawer pluginId="echo" isOpen onClose={vi.fn()} onRollback={onRollback} />
    </QueryClientProvider>,
  )
  return onRollback
}

describe('PluginDetailsDrawer', () => {
  test('the last 200 log lines, and a refresh that reads them again', async () => {
    show()
    const log = await screen.findByTestId('plugin-log')
    await waitFor(() => expect(log.textContent).toMatch(/worker started: pid 42/))
    expect(log.textContent).toMatch(/Traceback/)
    expect(calls).toContain('/api/plugins/echo/logs?lines=200')
    logs = { status: 200, body: { lines: ['1.1.0 a new line'] } }
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }))
    await waitFor(() => expect(screen.getByTestId('plugin-log').textContent).toMatch(/a new line/))
    expect(calls.filter((c) => c.startsWith('/api/plugins/echo/logs')).length).toBeGreaterThanOrEqual(2)
  })

  test('the runner down: the log says why, the rest still shows', async () => {
    logs = { status: 503, body: { error: 'The plugin runner could not be reached.', code: 'runner_unavailable' } }
    show()
    expect(await screen.findByText(/runner is unavailable/i)).toBeTruthy()
    expect(screen.getByText(/worker_failed: the worker is failed/)).toBeTruthy()
  })

  test('an empty log', async () => {
    logs = { status: 200, body: { lines: [] } }
    show()
    expect(await screen.findByText(/nothing logged/i)).toBeTruthy()
  })

  test('last error, versions on disk, permissions, data usage, versions, export', async () => {
    show()
    expect(await screen.findByText(/worker_failed: the worker is failed/)).toBeTruthy()
    const versions = screen.getByTestId('plugin-versions')
    expect(within(versions).getByText(/1\.1\.0/).textContent).toMatch(/active/)
    expect(within(versions).getByText(/1\.0\.0/).textContent).toMatch(/previous/)
    expect(screen.getByText('Read chat sessions')).toBeTruthy()
    const data = screen.getByTestId('plugin-data').textContent!
    expect(data).toMatch(/1,234 of 10,000 rows/)
    expect(data).toMatch(/2\.5 MB of 50\.0 MB/)
    expect(screen.getByTestId('plugin-overrides').textContent).toMatch(/2 approved skill versions, not applied/)
    // Fetched by the page, so a refusal is shown instead of being saved as the export.
    expect(screen.getByRole('button', { name: /export data/i })).toBeTruthy()
  })

  test('while an operation runs the rollback button waits', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <PluginDetailsDrawer pluginId="echo" isOpen busy onClose={vi.fn()} onRollback={vi.fn()} />
      </QueryClientProvider>,
    )
    expect(((await screen.findByRole('button', { name: /roll back to 1\.0\.0/i })) as HTMLButtonElement).disabled).toBe(true)
  })

  test('rollback offered when possible, with a warning when it moves data', async () => {
    const onRollback = show()
    const button = await screen.findByRole('button', { name: /roll back to 1\.0\.0/i })
    expect(screen.getByText(/data back/i)).toBeTruthy()
    fireEvent.click(button)
    expect(onRollback).toHaveBeenCalledWith('echo', '1.0.0')
  })

  test.each([
    [{ possible: false, reason: 'no_down_migration', missing: ['migrations/0003_down.py'] }, /ships no way back.*0003_down/],
    [{ possible: false, reason: 'no_previous_version' }, /no previous version/i],
    [{ possible: false, reason: 'platform_incompatible' }, /needs a different RedAmon/i],
  ])('rollback not possible (%j): the reason, no button', async (rollback, why) => {
    detail = detailOf({ rollback })
    show()
    expect(await screen.findByText(why)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /roll back/i })).toBeNull()
  })
})
