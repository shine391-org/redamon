/**
 * Scan Timeline — Version Manager (Section 5 + 4A.5 + 8.7).
 *
 * The UI is the last gate before three irreversible things: activating a version
 * (swaps the live graph), deleting one (drops its bytes), and saving the current
 * graph. Each must be explicitly confirmed, and the affordances must be disabled
 * exactly where the server would refuse anyway.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'

const alertError = vi.fn()
const dangerConfirm = vi.fn()
const toastInfo = vi.fn()

vi.mock('@/components/ui', () => ({
  Modal: ({ isOpen, children, title, headerActions }: {
    isOpen: boolean; children: React.ReactNode; title?: string; headerActions?: React.ReactNode
  }) =>
    isOpen ? <div role="dialog" aria-label={title}>{headerActions}{children}</div> : null,
  WikiInfoButton: ({ target, title }: { target: string; title?: string }) =>
    <a href={`#${target}`} aria-label={title}>wiki</a>,
  useAlertModal: () => ({ alertError, dangerConfirm }),
  useToast: () => ({ info: toastInfo }),
}))

import { VersionManager } from './VersionManager'
import type { ScanVersionSummary } from '../../hooks/useScanVersions'

const v = (over: Partial<ScanVersionSummary>): ScanVersionSummary => ({
  id: 'v1', seq: 1, label: 'Scan 1', isCurrent: false, pinned: false,
  nodeCount: 10, linkCount: 5, createdAt: '2026-07-01T10:00:00.000Z',
  snapshotBytes: 4096, activatable: true, ...over,
})

const versions = [
  v({ id: 'v3', seq: 3, label: 'Scan 3', isCurrent: true, snapshotBytes: 0, activatable: false }),
  v({ id: 'v2', seq: 2, label: 'Scan 2' }),
  v({ id: 'v1', seq: 1, label: 'Scan 1 (legacy)', snapshotBytes: 0, activatable: false }),
  v({ id: 'v0', seq: 0, label: 'Pinned baseline', pinned: true }),
]

const props = {
  isOpen: true,
  onClose: vi.fn(),
  projectId: 'p1',
  versions,
  onChanged: vi.fn(),
  onActivated: vi.fn(),
  selectedVersionId: null,
  onSelectVersion: vi.fn(),
}

let fetchMock: ReturnType<typeof vi.fn>
const rowFor = (label: string) => screen.getByText(label).closest('tr')!

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('the active row reports what the live scan is doing', () => {
  test('a running recon is called out on the active version, not on the others', () => {
    render(<VersionManager {...props} liveScanStatus="running" />)
    expect(within(rowFor('Scan 3')).getByText('Running')).toBeTruthy()
    expect(within(rowFor('Scan 2')).queryByText('Running')).toBeNull()
  })

  test('the optimistic pausing state is shown too', () => {
    render(<VersionManager {...props} liveScanStatus="pausing" />)
    expect(within(rowFor('Scan 3')).getByText('Pausing')).toBeTruthy()
  })

  test('an idle project shows no scan badge at all', () => {
    render(<VersionManager {...props} liveScanStatus="idle" />)
    expect(screen.queryByText('Running')).toBeNull()
    expect(within(rowFor('Scan 3')).getByText('Active')).toBeTruthy()
  })
})

describe('affordances match what the server allows', () => {
  test('the current version cannot be activated or deleted', () => {
    render(<VersionManager {...props} />)
    const row = rowFor('Scan 3')
    expect(within(row).getByText('Activate').closest('button')!.disabled).toBe(true)
    expect((within(row).getByTitle(/cannot be deleted/i) as HTMLButtonElement).disabled).toBe(true)
    expect(within(row).getByText('Active')).toBeTruthy()
  })

  test('a version with no stored snapshot is flagged and non-activatable (4A.6)', () => {
    render(<VersionManager {...props} />)
    const row = rowFor('Scan 1 (legacy)')
    expect(within(row).getByText('No snapshot')).toBeTruthy()
    expect(within(row).getByText('Activate').closest('button')!.disabled).toBe(true)
    // There is nothing to render either, so viewing it is disabled too.
    expect(within(row).getByText('View').closest('button')!.disabled).toBe(true)
  })

  test('a pinned version must be unpinned before it can be deleted', () => {
    render(<VersionManager {...props} />)
    const row = rowFor('Pinned baseline')
    expect(within(row).getByText('Pinned')).toBeTruthy()
    expect((within(row).getByTitle(/unpin it first/i) as HTMLButtonElement).disabled).toBe(true)
  })

  test('a restorable past version can be activated', () => {
    render(<VersionManager {...props} />)
    expect(within(rowFor('Scan 2')).getByText('Activate').closest('button')!.disabled).toBe(false)
  })
})

describe('destructive actions are confirmed', () => {
  test('activate asks first, and declining does nothing', async () => {
    dangerConfirm.mockResolvedValue(false)
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByText('Activate'))
    await waitFor(() => expect(dangerConfirm).toHaveBeenCalled())
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('the activate confirm states what happens, including the F2 artifact caveat', async () => {
    dangerConfirm.mockResolvedValue(false)
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByText('Activate'))
    await waitFor(() => expect(dangerConfirm).toHaveBeenCalled())
    const [message, title] = dangerConfirm.mock.calls[0]
    expect(title).toMatch(/activate/i)
    expect(message).toMatch(/save the current graph as a version/i)
    expect(message).toMatch(/Scan 2/)
    expect(message).toMatch(/remediations|captured traffic|reports/i)
  })

  test('accepting activate posts and reports back to the page', async () => {
    dangerConfirm.mockResolvedValue(true)
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByText('Activate'))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/projects/p1/versions/v2/activate',
      expect.objectContaining({ method: 'POST' })
    ))
    await waitFor(() => expect(props.onActivated).toHaveBeenCalledWith('v2'))
    expect(props.onChanged).toHaveBeenCalled()
    // The viewer returns to the live graph, which is now this version.
    expect(props.onSelectVersion).toHaveBeenCalledWith(null)
  })

  test('a failed activation surfaces the server reason and does not claim success', async () => {
    dangerConfirm.mockResolvedValue(true)
    fetchMock.mockResolvedValue({
      ok: false, status: 409,
      json: async () => ({ error: 'Cannot activate a version while a full recon scan is running' }),
    })
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByText('Activate'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Cannot activate a version while a full recon scan is running (HTTP 409)',
      'Could not activate the version'
    ))
    expect(props.onActivated).not.toHaveBeenCalled()
  })

  test('a gateway timeout says the activation may still be running and reloads the list', async () => {
    dangerConfirm.mockResolvedValue(true)
    fetchMock.mockResolvedValue({ ok: false, status: 504, text: async () => '<html>Gateway Time-out</html>' })
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByText('Activate'))
    await waitFor(() => expect(alertError).toHaveBeenCalled())
    const [message, title] = alertError.mock.calls[0]
    expect(title).toBe('Could not activate the version')
    expect(message).toMatch(/^Could not activate the version \(non_json_response · HTTP 504\)/)
    expect(message).toMatch(/may still be running or may already have finished/)
    expect(props.onChanged).toHaveBeenCalled()
    expect(props.onActivated).not.toHaveBeenCalled()
  })

  test('a freeze failure shows the fixed reason with its code, never the exception text', async () => {
    dangerConfirm.mockResolvedValue(true)
    fetchMock.mockResolvedValue({
      ok: false, status: 500,
      json: async () => ({
        error: 'Could not save the current graph before switching, so nothing was changed.',
        code: 'P2024', freezeFailed: true,
      }),
    })
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByText('Activate'))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Could not save the current graph before switching, so nothing was changed. (P2024 · HTTP 500)',
      'Could not activate the version'
    ))
    expect(props.onChanged).not.toHaveBeenCalled()
  })

  test('an activation that got no answer at all is reported, not left as an unhandled rejection', async () => {
    dangerConfirm.mockResolvedValue(true)
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByText('Activate'))
    await waitFor(() => expect(alertError).toHaveBeenCalled())
    expect(alertError.mock.calls[0][0]).toMatch(/^Could not activate the version \(network_error\)/)
  })

  test('delete asks first and names the bytes being dropped', async () => {
    dangerConfirm.mockResolvedValue(false)
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByTitle(/Delete this version/i))
    await waitFor(() => expect(dangerConfirm).toHaveBeenCalled())
    expect(dangerConfirm.mock.calls[0][0]).toMatch(/4\.0 KB/)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('non-destructive edits', () => {
  test('rename PATCHes the new label', async () => {
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByTitle('Rename'))
    const input = screen.getByDisplayValue('Scan 2')
    fireEvent.change(input, { target: { value: 'Before the migration' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(c => c[1]?.method === 'PATCH')
      expect(JSON.parse(patch![1].body)).toEqual({ label: 'Before the migration' })
    })
  })

  test('escape cancels a rename without calling the server', async () => {
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByTitle('Rename'))
    const input = screen.getByDisplayValue('Scan 2')
    fireEvent.change(input, { target: { value: 'nope' } })
    fireEvent.keyDown(input, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByDisplayValue('nope')).toBeNull())
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('pin toggles without a confirm', async () => {
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByTitle(/^Pin/))
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(c => c[1]?.method === 'PATCH')
      expect(JSON.parse(patch![1].body)).toEqual({ pinned: true })
    })
    expect(dangerConfirm).not.toHaveBeenCalled()
  })

  test('save-current posts to the collection endpoint', async () => {
    render(<VersionManager {...props} />)
    fireEvent.click(screen.getByText(/Save current graph as a version/i))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/projects/p1/versions',
      expect.objectContaining({ method: 'POST' })
    ))
  })

  test('a refused save-current (e.g. a scan is running) is surfaced', async () => {
    fetchMock.mockResolvedValue({
      ok: false, status: 409,
      json: async () => ({ error: 'Cannot save a version while a full recon scan is running' }),
    })
    render(<VersionManager {...props} />)
    fireEvent.click(screen.getByText(/Save current graph as a version/i))
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Cannot save a version while a full recon scan is running (HTTP 409)',
      'Could not save the current graph as a version'
    ))
  })

  test('a rename the network dropped says so instead of failing silently', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    render(<VersionManager {...props} />)
    fireEvent.click(within(rowFor('Scan 2')).getByTitle('Rename'))
    const input = screen.getByDisplayValue('Scan 2')
    fireEvent.change(input, { target: { value: 'Renamed' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Could not rename the version (network_error)',
      'Could not rename the version'
    ))
    // Only an activation's outcome is unknown; a rename is simply not done.
    expect(props.onChanged).not.toHaveBeenCalled()
  })
})
