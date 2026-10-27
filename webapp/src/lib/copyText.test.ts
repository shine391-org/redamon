/**
 * copyText's legacy path (plain http, no Clipboard API) must leave focus where
 * it found it. Chrome moves focus to the hidden textarea on select(); once the
 * textarea is removed focus lands on <body>, where a Modal's Escape handler (an
 * onKeyDown on the dialog) no longer fires.
 *
 * Run: npx vitest run src/lib/copyText.test.ts
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { copyText } from './copyText'

let button: HTMLButtonElement

beforeEach(() => {
  Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
  // jsdom's select() leaves focus alone; Chrome's focuses the textarea.
  vi.spyOn(HTMLTextAreaElement.prototype, 'select').mockImplementation(function (this: HTMLTextAreaElement) {
    this.focus()
    this.setSelectionRange(0, this.value.length)
  })
  button = document.createElement('button')
  document.body.appendChild(button)
  button.focus()
})

afterEach(() => {
  vi.restoreAllMocks()
  button.remove()
  delete (navigator as { clipboard?: unknown }).clipboard
  delete (document as { execCommand?: unknown }).execCommand
})

function stubExecCommand(result: boolean) {
  const copied: string[] = []
  const exec = vi.fn(() => {
    const el = document.activeElement
    if (el instanceof HTMLTextAreaElement) copied.push(el.value.slice(el.selectionStart, el.selectionEnd))
    return result
  })
  Object.defineProperty(document, 'execCommand', { value: exec, configurable: true, writable: true })
  return copied
}

describe('copyText without the Clipboard API', () => {
  test('copies the text and gives focus back to the clicked button', async () => {
    const copied = stubExecCommand(true)
    await copyText('rate limiting not tested')
    expect(copied).toEqual(['rate limiting not tested'])
    expect(document.activeElement).toBe(button)
    expect(document.querySelector('textarea')).toBeNull()
  })

  test('gives focus back when the copy fails too', async () => {
    stubExecCommand(false)
    await expect(copyText('x')).rejects.toThrow('copy failed')
    expect(document.activeElement).toBe(button)
    expect(document.querySelector('textarea')).toBeNull()
  })
})
