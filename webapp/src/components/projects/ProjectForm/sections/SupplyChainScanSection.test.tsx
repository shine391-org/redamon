/**
 * Supply Chain Scanner section: the L1 scan's input, which moved here from the
 * Other Scans card so that card could keep the run controls only.
 *
 * What this guards: the selected source is PERSISTED as the project's input mode
 * (including 'org', which the card reads to decide between Start and the queue
 * action), and an upload - which is written immediately, outside the form's Save
 * - is mirrored back into the form. Without that mirror, saving the form after
 * an upload writes back the stale file name it was loaded with and silently
 * un-points the scan.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/SupplyChainScanSection.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useState } from 'react'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { SupplyChainScanSection } from './SupplyChainScanSection'

type Data = Record<string, unknown>

let fetchMock: ReturnType<typeof vi.fn>

const NO_FILES = { files: [] as unknown[] }

function stubFetch(files: unknown[] = []) {
  fetchMock = vi.fn().mockImplementation((url: string, init?: { method?: string }) => {
    if (init?.method === 'POST') {
      return Promise.resolve({ ok: true, json: async () => ({ success: true, filename: 'sbom.json' }) })
    }
    if (init?.method === 'DELETE') {
      return Promise.resolve({ ok: true, json: async () => ({ success: true }) })
    }
    if (String(url).includes('/upload')) {
      return Promise.resolve({ ok: true, json: async () => ({ files }) })
    }
    return Promise.resolve({ ok: true, json: async () => ({}) })
  })
  vi.stubGlobal('fetch', fetchMock)
}

beforeEach(() => {
  vi.clearAllMocks()
  stubFetch()
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/** Stateful, exactly like ProjectForm: updateField feeds straight back as data. */
function Harness({ initial, onChange }: { initial: Data; onChange: (k: string, v: unknown) => void }) {
  const [data, setData] = useState<Data>(initial)
  return (
    <SupplyChainScanSection
      data={data as never}
      updateField={((key: string, value: unknown) => {
        onChange(key, value)
        setData(d => ({ ...d, [key]: value }))
      }) as never}
      projectId="p1"
      mode="edit"
    />
  )
}

function renderSection(initial: Data = {}) {
  const onChange = vi.fn()
  render(<Harness initial={{ supplyChainInputMode: 'upload', ...initial }} onChange={onChange} />)
  const written = (key: string) =>
    onChange.mock.calls.filter(c => c[0] === key).at(-1)?.[1]
  return { onChange, written }
}

describe('scan input source', () => {
  test('offers the three sources and persists the selected one', async () => {
    const { written } = renderSection()
    expect(screen.getByText('Uploaded SBOM / lockfile')).toBeTruthy()

    fireEvent.click(screen.getByText('GitHub repository'))
    expect(written('supplyChainInputMode')).toBe('github')
    await waitFor(() => expect(screen.getByLabelText('Repository')).toBeTruthy())

    // 'org' is persisted like the other two: the Other Scans card reads the mode
    // to decide whether to offer Start or the org batch, so a mode it cannot
    // save would leave a Start button there that can never be enabled.
    fireEvent.click(screen.getByText('GitHub organization'))
    expect(written('supplyChainInputMode')).toBe('org')
    await waitFor(() => expect(screen.getByLabelText('Organization or user')).toBeTruthy())
  })

  test('only the selected source is configurable', async () => {
    renderSection({ supplyChainInputMode: 'github' })
    await waitFor(() => expect(screen.getByLabelText('Repository')).toBeTruthy())
    expect(screen.queryByLabelText('Organization or user')).toBeNull()
    expect(screen.queryByLabelText('Upload SBOM or lockfile')).toBeNull()
  })
})

describe('uploaded SBOM / lockfile', () => {
  test('lists the file already uploaded for the project', async () => {
    stubFetch([{ name: 'package-lock.json', size: 2048, uploaded_at: '2026-08-01T00:00:00Z' }])
    renderSection()
    await waitFor(() => expect(screen.getByText('package-lock.json')).toBeTruthy())
    expect(screen.getByText('(2.0 KB)')).toBeTruthy()
  })

  test('an upload is mirrored into the form so Save cannot un-point the scan', async () => {
    const { written } = renderSection()
    await waitFor(() => expect(screen.getByText('No file uploaded yet.')).toBeTruthy())

    const input = screen.getByLabelText('Upload SBOM or lockfile')
    fireEvent.change(input, { target: { files: [new File(['{}'], 'sbom.json')] } })

    await waitFor(() => expect(written('supplyChainSbomFile')).toBe('sbom.json'))
    const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')
    expect(String(post![0])).toBe('/api/supply-chain/p1/upload')
  })

  test('removing the file clears it as the scan input', async () => {
    stubFetch([{ name: 'package-lock.json', size: 10, uploaded_at: '2026-08-01T00:00:00Z' }])
    const { written } = renderSection()
    await waitFor(() => expect(screen.getByLabelText('Remove package-lock.json')).toBeTruthy())

    fireEvent.click(screen.getByLabelText('Remove package-lock.json'))
    await waitFor(() => expect(written('supplyChainSbomFile')).toBe(''))
    const del = fetchMock.mock.calls.find(c => c[1]?.method === 'DELETE')
    expect(String(del![0])).toBe('/api/supply-chain/p1/upload?filename=package-lock.json')
  })

  // Uploads are written against a project row, so there is nothing to upload to
  // before the project is saved.
  test('create mode explains that the project must be saved first', () => {
    render(
      <SupplyChainScanSection
        data={{ supplyChainInputMode: 'upload' } as never}
        updateField={(() => {}) as never}
        projectId={null}
        mode="create"
      />
    )
    expect(screen.getByText(/Save the project first/)).toBeTruthy()
    expect(screen.queryByLabelText('Upload SBOM or lockfile')).toBeNull()
  })
})

describe('repository and organization targets', () => {
  test('a malformed repository is called out before it can be saved', async () => {
    renderSection({ supplyChainInputMode: 'github' })
    const repo = await screen.findByLabelText('Repository')
    fireEvent.change(repo, { target: { value: 'http://evil.example.com/a/b' } })
    await waitFor(() => expect(screen.getByText(/Must be a repository as owner\/repo/)).toBeTruthy())
  })

  test('a repository URL is not an account', async () => {
    renderSection({ supplyChainInputMode: 'org' })
    const org = await screen.findByLabelText('Organization or user')
    fireEvent.change(org, { target: { value: 'https://github.com/acme-corp/some-repo' } })
    await waitFor(() => expect(screen.getByText(/letters, digits and dashes/)).toBeTruthy())
  })

  // GitHub Enterprise: the field takes a URL as well as a name. Which HOSTS are
  // reachable is the server's decision (it owns the operator's allowlist), so a
  // well-formed target is accepted here and refused there if the host is unknown.
  test('a GitHub Enterprise org URL is accepted and persisted', async () => {
    const { written } = renderSection({ supplyChainInputMode: 'org' })
    const org = await screen.findByLabelText('Organization or user')
    fireEvent.change(org, { target: { value: 'https://ghe.example.com/orgs/acme-corp' } })
    expect(screen.queryByText(/letters, digits and dashes/)).toBeNull()
    expect(written('supplyChainOrgName')).toBe('https://ghe.example.com/orgs/acme-corp')
  })
})

describe('failures keep their cause', () => {
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
  const FILE = { name: 'package-lock.json', size: 10, uploaded_at: '2026-08-01T00:00:00Z' }

  function route(replies: { list?: () => Response; upload?: () => Response; remove?: () => Response }) {
    fetchMock = vi.fn().mockImplementation(async (url: string, init?: { method?: string }) => {
      if (init?.method === 'POST') return replies.upload ? replies.upload() : json(200, { success: true, filename: 'sbom.json' })
      if (init?.method === 'DELETE') return replies.remove ? replies.remove() : json(200, { success: true })
      if (String(url).includes('/upload')) return replies.list ? replies.list() : json(200, { files: [FILE] })
      return json(200, {})
    })
    vi.stubGlobal('fetch', fetchMock)
  }

  test('a failed listing is an error with the fs code, not "No file uploaded yet"', async () => {
    route({ list: () => json(500, { error: 'Failed to list files', code: 'EACCES' }) })
    renderSection()
    expect((await screen.findByRole('alert')).textContent).toBe('Failed to list files (EACCES · HTTP 500)')
    expect(screen.queryByText('No file uploaded yet.')).toBeNull()
  })

  test('a failed upload shows the fs code and status', async () => {
    route({ list: () => json(200, { files: [] }), upload: () => json(500, { error: 'Failed to upload file', code: 'ENOSPC' }) })
    const { written } = renderSection()
    await waitFor(() => expect(screen.getByText('No file uploaded yet.')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('Upload SBOM or lockfile'), { target: { files: [new File(['{}'], 'sbom.json')] } })
    await waitFor(() => expect(screen.getByText('Failed to upload file (ENOSPC · HTTP 500)')).toBeTruthy())
    expect(written('supplyChainSbomFile')).toBeUndefined()
  })

  test('a proxy error page on upload is named, not the bare fallback', async () => {
    route({
      list: () => json(200, { files: [] }),
      upload: () => new Response('<html>502 Bad Gateway</html>', { status: 502 }),
    })
    renderSection()
    await waitFor(() => expect(screen.getByText('No file uploaded yet.')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('Upload SBOM or lockfile'), { target: { files: [new File(['{}'], 'sbom.json')] } })
    await waitFor(() => expect(screen.getByText('Upload failed (non_json_response · HTTP 502)')).toBeTruthy())
  })

  test('a failed delete keeps the file as the scan input and says why', async () => {
    route({ remove: () => json(500, { error: 'Failed to delete file', code: 'EROFS' }) })
    const { written } = renderSection()
    fireEvent.click(await screen.findByLabelText('Remove package-lock.json'))
    await waitFor(() => expect(screen.getByText('Failed to delete file (EROFS · HTTP 500)')).toBeTruthy())
    expect(written('supplyChainSbomFile')).toBeUndefined()
    expect(screen.getByText('package-lock.json')).toBeTruthy()
  })

  test('a delete that got no answer keeps the file too', async () => {
    route({ remove: () => { throw new TypeError('Failed to fetch') } })
    const { written } = renderSection()
    fireEvent.click(await screen.findByLabelText('Remove package-lock.json'))
    await waitFor(() => expect(screen.getByText('Could not remove the file (network_error)')).toBeTruthy())
    expect(written('supplyChainSbomFile')).toBeUndefined()
  })
})
