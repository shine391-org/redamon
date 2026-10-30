/**
 * Install from files: the browser finds the release the uploaded catalog pins for the
 * archive's SHA-256, only to show its permissions for consent; the server checks everything
 * again. Install needs the three files, a listed archive and the ticked consent.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { createHash, webcrypto } from 'node:crypto'
import { OfflineInstallDialog } from './OfflineInstallDialog'

// jsdom's crypto has no subtle; every browser that runs the page has it.
beforeEach(() => vi.stubGlobal('crypto', webcrypto))
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const ARCHIVE = Buffer.from('pretend this is a gzip archive')
const SHA = createHash('sha256').update(ARCHIVE).digest('hex')
const catalog = (sha: string, release: Record<string, unknown> = {}) =>
  JSON.stringify({
    plugins: [{ id: 'echo', displayName: 'Echo', releases: [{ version: '1.0.0', sha256: sha, permissions: ['session:read'], dataVersion: 1, ...release }] }],
  })

function pick(index: number, name: string, content: string | Buffer) {
  const input = document.querySelectorAll('input[type="file"]')[index] as HTMLInputElement
  const file = new File([new Uint8Array(Buffer.from(content))], name)
  fireEvent.change(input, { target: { files: [file] } })
}

describe('OfflineInstallDialog', () => {
  test('a listed archive: its permissions, consent, then the form with the accepted list', async () => {
    const onSubmit = vi.fn()
    render(<OfflineInstallDialog isOpen onSubmit={onSubmit} onCancel={vi.fn()} />)
    pick(0, 'echo-1.0.0.tar.gz', ARCHIVE)
    pick(1, 'catalog.json', catalog(SHA))
    pick(2, 'catalog.json.sig', '{"keyId":"k","sig":"x"}')
    expect(await screen.findByText('Read chat sessions')).toBeTruthy()
    expect(screen.getByText('echo-1.0.0.tar.gz')).toBeTruthy()
    expect(screen.getAllByText('Change')).toHaveLength(3)
    const install = screen.getByRole('button', { name: /^Install Echo 1\.0\.0/ }) as HTMLButtonElement
    expect(install.disabled).toBe(true)
    fireEvent.click(screen.getByRole('checkbox'))
    expect(install.disabled).toBe(false)
    fireEvent.click(install)
    expect(onSubmit).toHaveBeenCalledTimes(1)
    const form = onSubmit.mock.calls[0][0] as FormData
    expect(form.get('acceptedPermissions')).toBe('["session:read"]')
    expect((form.get('archive') as File).name).toBe('echo-1.0.0.tar.gz')
    expect((form.get('signature') as File).name).toBe('catalog.json.sig')
  })

  test('an archive the catalog does not list: no install', async () => {
    render(<OfflineInstallDialog isOpen onSubmit={vi.fn()} onCancel={vi.fn()} />)
    pick(0, 'other.tar.gz', ARCHIVE)
    pick(1, 'catalog.json', catalog('0'.repeat(64)))
    expect(await screen.findByText(/does not list this archive/)).toBeTruthy()
    expect((screen.getByRole('button', { name: /^Install$/ }) as HTMLButtonElement).disabled).toBe(true)
  })

  test('an installed plugin: the upload is an update, with the permissions it adds and the data warning', async () => {
    const onSubmit = vi.fn()
    render(
      <OfflineInstallDialog
        isOpen
        installed={{ echo: { version: '1.0.0', dataVersion: 1, grantedPermissions: ['session:read'] } }}
        onSubmit={onSubmit}
        onCancel={vi.fn()}
      />,
    )
    pick(0, 'echo-1.1.0.tar.gz', ARCHIVE)
    pick(1, 'catalog.json', catalog(SHA, { version: '1.1.0', permissions: ['session:read', 'llm:invoke'], dataVersion: 2 }))
    pick(2, 'catalog.json.sig', '{"keyId":"k","sig":"x"}')
    expect(await screen.findByText(/updates Echo from 1\.0\.0 to 1\.1\.0/)).toBeTruthy()
    const llm = screen.getByText('Use a language model').closest('li')!
    expect(llm.textContent).toMatch(/New/)
    expect(screen.getByText('Read chat sessions').closest('li')!.textContent).not.toMatch(/New/)
    expect(screen.getByText(/moves the plugin's data to a new format/)).toBeTruthy()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /^Update Echo 1\.1\.0/ }))
    expect(onSubmit).toHaveBeenCalledTimes(1)
  })

  test('the restore question the server asked: answered in the form', async () => {
    const onSubmit = vi.fn()
    render(<OfflineInstallDialog isOpen restoreCount={2} onSubmit={onSubmit} onCancel={vi.fn()} />)
    pick(0, 'echo-1.0.0.tar.gz', ARCHIVE)
    pick(1, 'catalog.json', catalog(SHA))
    pick(2, 'catalog.json.sig', '{"keyId":"k","sig":"x"}')
    expect(await screen.findByText(/left 2 approved skill versions/)).toBeTruthy()
    fireEvent.click(screen.getByRole('radio', { name: /factory text/i }))
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /^Install Echo 1\.0\.0/ }))
    expect((onSubmit.mock.calls[0][0] as FormData).get('restoreOverrides')).toBe('false')
  })

  test('a file that is not a catalog', async () => {
    render(<OfflineInstallDialog isOpen onSubmit={vi.fn()} onCancel={vi.fn()} />)
    pick(0, 'echo.tar.gz', ARCHIVE)
    pick(1, 'catalog.json', 'not json')
    await waitFor(() => expect(screen.getByText('The catalog file is not JSON, so it is not a plugin catalog.')).toBeTruthy())
  })

  // Plain HTTP on a host other than localhost (a redamon-http deploy): no WebCrypto at all.
  test('a page without WebCrypto says it needs HTTPS, not that the catalog is wrong', async () => {
    vi.stubGlobal('crypto', { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) })
    render(<OfflineInstallDialog isOpen onSubmit={vi.fn()} onCancel={vi.fn()} />)
    pick(0, 'echo.tar.gz', ARCHIVE)
    pick(1, 'catalog.json', catalog(SHA))
    await waitFor(() => expect(screen.getByText(/not served over HTTPS \(or localhost\)/)).toBeTruthy())
    expect(screen.queryByText(/not a plugin catalog/)).toBeNull()
  })
})
