/**
 * A Tradecraft resource save that failed shows its cause.
 *
 * The form used to show the route's fixed sentence alone ("Failed to update
 * tradecraft resource"), so a database timeout, a value too long for its column
 * and a dropped connection all read the same. It now carries the code and the
 * HTTP status, and a request that got no answer says so.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { GATE_USER, jsonResponse, stubGateFetch } from '@/components/shared/featureModelGate.testUtils'
import { FeatureModelGateProvider } from '@/components/shared/FeatureModelGate'
import { AlertProvider } from '@/components/ui/AlertModal/AlertModal'
import { TradecraftResourceForm } from './TradecraftResourceForm'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: GATE_USER }) }))

const RESOURCE_URL = `/api/users/${GATE_USER}/tradecraft-resources/r1`
const RESOURCE = { id: 'r1', name: 'HackTricks', url: 'https://book.hacktricks.wiki', enabled: true, llmModel: 'claude-haiku-4-5' }
// A saved picker model, so the save is not interrupted by the gate's prompt.
const SAVED = { tradecraft_section_picker: 'claude-haiku-4-5' }

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderAndSave(onSave = vi.fn()) {
  render(
    <AlertProvider>
      <FeatureModelGateProvider>
        <TradecraftResourceForm userId={GATE_USER} resource={RESOURCE} onSave={onSave} onCancel={vi.fn()} />
      </FeatureModelGateProvider>
    </AlertProvider>,
  )
  fireEvent.click(screen.getByRole('checkbox', { name: /Enabled/ }))
  fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))
  return onSave
}

describe('Tradecraft resource save errors', () => {
  test('a database failure shows its code and status', async () => {
    stubGateFetch(SAVED, (url) => url === RESOURCE_URL
      ? jsonResponse(500, { error: 'Failed to update tradecraft resource', code: 'P2000' })
      : jsonResponse(404, {}))
    const onSave = renderAndSave()
    expect(await screen.findByText('Failed to update tradecraft resource (P2000 · HTTP 500)')).toBeInTheDocument()
    expect(onSave).not.toHaveBeenCalled()
  })

  test('a proxy error page names its status instead of nothing', async () => {
    stubGateFetch(SAVED, (url) => url === RESOURCE_URL
      ? new Response('<html>502 Bad Gateway</html>', { status: 502 })
      : jsonResponse(404, {}))
    renderAndSave()
    expect(await screen.findByText('Failed to update the resource (non_json_response · HTTP 502)')).toBeInTheDocument()
  })

  test('no answer at all reads as a network failure', async () => {
    stubGateFetch(SAVED, (url) => {
      if (url === RESOURCE_URL) throw new TypeError('Failed to fetch')
      return jsonResponse(404, {})
    })
    renderAndSave()
    expect(await screen.findByText('Failed to update the resource (network_error)')).toBeInTheDocument()
  })
})
