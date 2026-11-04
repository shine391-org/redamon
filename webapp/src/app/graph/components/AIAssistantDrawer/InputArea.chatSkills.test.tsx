/**
 * The chat drawer's Chat Skills picker says why a call failed (U-11, U-12, G-42): an import or
 * an upload the server refused used to do nothing at all, and a list that could not be read
 * looked like no skills.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const ui = vi.hoisted(() => ({ alert: vi.fn(), alertError: vi.fn() }))
vi.mock('@/components/ui', () => ({ useAlertModal: () => ui }))

import { InputArea } from './InputArea'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

let routes: Record<string, () => Response | Promise<Response>>

beforeEach(() => {
  vi.clearAllMocks()
  routes = {
    'GET /api/users/alice/chat-skills': () => json(200, []),
  }
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const handler = routes[`${init?.method ?? 'GET'} ${url}`]
    return handler ? handler() : json(404, {})
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function draw() {
  return render(
    <InputArea
      inputRef={{ current: null }}
      inputValue=""
      handleInputChange={vi.fn()}
      handleKeyDown={vi.fn()}
      handleSend={vi.fn()}
      handleStop={vi.fn()}
      handleResume={vi.fn()}
      isConnected
      isLoading={false}
      isStopped={false}
      isStopping={false}
      awaitingApproval={false}
      awaitingQuestion={false}
      awaitingToolConfirmation={false}
      userId="alice"
      setInputValue={vi.fn()}
      activeSkill={null}
      setActiveSkill={vi.fn()}
      onSkillActivate={vi.fn()}
      userResizedRef={{ current: false }}
    />,
  )
}

async function openPicker() {
  await waitFor(() => expect(fetch).toHaveBeenCalled())
  fireEvent.click(screen.getByRole('button', { name: 'Browse skills' }))
}

describe('Chat Skills in the drawer', () => {
  test('a list that cannot be read says why, not "No Chat Skills yet"', async () => {
    routes['GET /api/users/alice/chat-skills'] = () => json(500, { error: 'Failed to fetch chat skills', code: 'P1001' })
    draw()
    await openPicker()
    expect(await screen.findByText('Failed to fetch chat skills (P1001 · HTTP 500)')).toBeInTheDocument()
    expect(screen.queryByText(/No Chat Skills yet/)).toBeNull()
  })

  test('a refused import alerts with the code and both statuses (it did nothing)', async () => {
    routes['POST /api/users/alice/chat-skills/import-community'] = () => json(502, {
      error: 'Failed to fetch skills catalog from agent service', code: 'agent_error', upstreamStatus: 500,
    })
    draw()
    await openPicker()
    fireEvent.mouseDown(screen.getByRole('button', { name: /Import from Community/ }))
    await waitFor(() => expect(ui.alertError).toHaveBeenCalledWith(
      'Failed to fetch skills catalog from agent service (agent_error · HTTP 502 · upstream HTTP 500)'))
  })

  test('an import that got no answer says network_error', async () => {
    routes['POST /api/users/alice/chat-skills/import-community'] = () => { throw new TypeError('Failed to fetch') }
    draw()
    await openPicker()
    fireEvent.mouseDown(screen.getByRole('button', { name: /Import from Community/ }))
    await waitFor(() => expect(ui.alertError).toHaveBeenCalledWith('Failed to import community chat skills (network_error)'))
  })

  test('the import summary names why skills were skipped, not "already exist" for all', async () => {
    routes['POST /api/users/alice/chat-skills/import-community'] = () => json(200, {
      imported: 1, skipped: 3, total: 4,
      skippedBy: { duplicate: 1, limit: 0, fetchFailed: 1, tooLarge: 0, invalid: 0, saveFailed: 1 },
    })
    draw()
    await openPicker()
    fireEvent.mouseDown(screen.getByRole('button', { name: /Import from Community/ }))
    await waitFor(() => expect(ui.alert).toHaveBeenCalledWith(
      'Imported 1 skill, 3 skipped (1 already exist, 1 could not be fetched, 1 could not be saved)'))
  })

  test('an answer that cannot be read is not reported as "Imported 0"', async () => {
    routes['POST /api/users/alice/chat-skills/import-community'] = () => new Response('not json', { status: 200 })
    draw()
    await openPicker()
    fireEvent.mouseDown(screen.getByRole('button', { name: /Import from Community/ }))
    await waitFor(() => expect(ui.alertError).toHaveBeenCalledWith(
      "Failed to read the import's answer (invalid_json · HTTP 200). Check your Chat Skills list."))
    expect(ui.alert).not.toHaveBeenCalled()
  })

  test("an upload the server refused shows the route's own reason with its status (it did nothing)", async () => {
    routes['POST /api/users/alice/chat-skills'] = () => json(400, { error: 'Maximum of 50 skills per user reached' })
    const { container } = draw()
    await waitFor(() => expect(fetch).toHaveBeenCalled())
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File(['# My skill'], 'my_skill.md', { type: 'text/markdown' })] } })
    await waitFor(() => expect(ui.alertError).toHaveBeenCalledWith('Maximum of 50 skills per user reached (HTTP 400)'))
  })
})
