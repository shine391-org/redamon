/**
 * Uninstall (README.PLUGINS.md §9.6, D-70): "Keep data" is the default; deleting everything
 * is instance-wide (every user and project), so it needs the export downloaded first and the
 * plugin id typed.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { UninstallDialog } from './UninstallDialog'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

/** The export answers 200 and is saved from a blob (jsdom has no object URLs or downloads). */
function exportServed() {
  const fetchMock = vi.fn(async (_url: string) => new Response('{"rows":[]}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
  URL.createObjectURL = vi.fn(() => 'blob:x')
  URL.revokeObjectURL = vi.fn()
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  return fetchMock
}

function open(busy = false) {
  const onConfirm = vi.fn()
  const onCancel = vi.fn()
  render(<UninstallDialog isOpen pluginId="echo" pluginName="Echo" busy={busy} onConfirm={onConfirm} onCancel={onCancel} />)
  return { onConfirm, onCancel }
}
const confirm = () => screen.getByRole('button', { name: /uninstall|delete everything/i }) as HTMLButtonElement

describe('UninstallDialog', () => {
  test('keep data is the default and uninstalls at once', () => {
    const { onConfirm } = open()
    expect((screen.getByRole('radio', { name: /keep its data/i }) as HTMLInputElement).checked).toBe(true)
    fireEvent.click(confirm())
    expect(onConfirm).toHaveBeenCalledWith('keep')
  })

  test('deleting all data says it is for every user and project', () => {
    open()
    expect(screen.getByRole('radio', { name: /delete all data for every user and project/i })).toBeTruthy()
  })

  test('purge needs the export downloaded and the plugin id typed', async () => {
    const fetchMock = exportServed()
    const { onConfirm } = open()
    fireEvent.click(screen.getByRole('radio', { name: /delete all data/i }))
    expect(confirm().disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', { name: /type echo/i }), { target: { value: 'echo' } })
    expect(confirm().disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: /download the export/i }))
    await waitFor(() => expect(confirm().disabled).toBe(false))
    expect(fetchMock.mock.calls[0][0]).toBe('/api/plugins/echo/export')
    expect(screen.getByRole('button', { name: /export downloaded/i })).toBeTruthy()
    fireEvent.change(screen.getByRole('textbox', { name: /type echo/i }), { target: { value: 'ech' } })
    expect(confirm().disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', { name: /type echo/i }), { target: { value: 'echo' } })
    fireEvent.click(confirm())
    expect(onConfirm).toHaveBeenCalledWith('purge')
  })

  test('kept data only: no keep choice, what goes, the export and the typed id', async () => {
    exportServed()
    const onConfirm = vi.fn()
    render(<UninstallDialog isOpen keptOnly pluginId="echo" pluginName="Echo" onConfirm={onConfirm} onCancel={vi.fn()} />)
    expect(screen.getByRole('dialog').textContent).toMatch(/not installed.*kept.*every user and project/i)
    expect(screen.queryByRole('radio')).toBeNull()
    const go = screen.getByRole('button', { name: 'Delete kept data' }) as HTMLButtonElement
    expect(go.disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: /download the export/i }))
    fireEvent.change(screen.getByRole('textbox', { name: /type echo/i }), { target: { value: 'echo' } })
    await waitFor(() => expect(go.disabled).toBe(false))
    fireEvent.click(go)
    expect(onConfirm).toHaveBeenCalledWith('purge')
  })

  test('cancel', () => {
    const { onCancel, onConfirm } = open()
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(onCancel).toHaveBeenCalled()
    expect(onConfirm).not.toHaveBeenCalled()
  })

  test('busy disables the confirmation', () => {
    open(true)
    expect(confirm().disabled).toBe(true)
  })
})
