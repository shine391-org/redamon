/**
 * The chat's copy buttons over plain http (http://<lan-ip>:3000), where the
 * page is not a secure context and `navigator.clipboard` is undefined: the
 * whole-message Copy and the per-cell copy in a markdown report table.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/ChatArea.copy.test.tsx
 */
import React, { createRef } from 'react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act, cleanup } from '@testing-library/react'
import { ChatArea } from './ChatArea'
import type { Message } from './types'

const REPORT = [
  '| Gap | Impact |',
  '| --- | --- |',
  '| Rate limiting not tested | Unknown if WAF would block |',
].join('\n')

const assistantMsg = (content: string): Message => ({
  type: 'message', id: 'a1', role: 'assistant', content, timestamp: new Date(),
})

function renderMessages(messages: Message[]) {
  return render(
    <ChatArea
      messagesContainerRef={createRef<HTMLDivElement>()}
      messagesEndRef={createRef<HTMLDivElement>()}
      checkIfAtBottom={() => true}
      chatItems={messages}
      groupedChatItems={messages.map(m => ({ type: 'message' as const, content: m }))}
      isLoading={false}
      todoList={[]}
      statusWord=""
      isConnected
      setInputValue={() => {}}
      missingApiKeys={new Set()}
      openApiKeyModal={() => {}}
      handleTimelineToolConfirmation={() => {}}
    />,
  )
}

/** jsdom has no execCommand; record what the hidden textarea held when copied. */
let copied: string[]

beforeEach(() => {
  Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
  copied = []
  const exec = vi.fn((cmd: string) => {
    const el = document.querySelector('body > textarea')
    if (cmd === 'copy' && el instanceof HTMLTextAreaElement) copied.push(el.value)
    return true
  })
  Object.defineProperty(document, 'execCommand', { value: exec, configurable: true, writable: true })
})

afterEach(() => {
  cleanup()
  delete (navigator as { clipboard?: unknown }).clipboard
  delete (document as { execCommand?: unknown }).execCommand
})

describe('ChatArea copy over plain http', () => {
  it('copies the whole assistant message and says so', async () => {
    renderMessages([assistantMsg(REPORT)])
    await act(async () => { fireEvent.click(screen.getByTitle('Copy to clipboard')) })
    expect(copied).toEqual([REPORT])
    expect(screen.getByTitle('Copy to clipboard').textContent).toContain('Copied')
  })

  it('copies a single report table cell', async () => {
    renderMessages([assistantMsg(REPORT)])
    await act(async () => { fireEvent.click(screen.getAllByTitle('Copy value')[0]) })
    expect(copied).toEqual(['Rate limiting not tested'])
    // The markdown renderers are inline components, so the cell remounts on
    // re-render; query the button again rather than holding the old node.
    expect(screen.getAllByTitle('Copy value')[0].querySelector('svg.lucide-check')).not.toBeNull()
  })
})
