/**
 * Copy text to the clipboard, including where the Clipboard API is missing.
 *
 * `navigator.clipboard` only exists in a secure context, and RedAmon is often
 * served over plain http on the LAN, where it is undefined. It can also reject
 * inside a secure context (permission denied, document not focused). Both fall
 * back to a hidden-textarea `execCommand('copy')`, which still works there.
 *
 * Rejects when neither path copied, so the caller can say so instead of
 * implying success.
 */
export async function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return
    } catch {
      // Fall through to the legacy path.
    }
  }
  const previousFocus = document.activeElement
  const el = document.createElement('textarea')
  el.value = text
  el.setAttribute('readonly', '')
  el.style.position = 'fixed'
  el.style.opacity = '0'
  document.body.appendChild(el)
  try {
    el.select()
    if (!document.execCommand('copy')) throw new Error('copy failed')
  } finally {
    document.body.removeChild(el)
    // select() moved focus to the textarea, so removing it leaves focus on
    // <body>: a Modal's Escape (an onKeyDown on the dialog) stops working and
    // a keyboard user loses their place. Hand focus back.
    if (previousFocus instanceof HTMLElement) previousFocus.focus({ preventScroll: true })
  }
}
