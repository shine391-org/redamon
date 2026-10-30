/**
 * The inline Global Settings credential editor.
 *
 * What this guards beyond "it renders": the shortcut writes a USER-level key
 * from inside a project form, so the two things it must never do are imply the
 * value is project-scoped, and imply it can show a stored secret. The API masks
 * secrets on read, so a box pre-filled with the mask would send '••••••••abcd'
 * back as the new token the moment the user pressed Save.
 *
 * Run: npx vitest run src/components/settings/CredentialShortcut.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { CredentialShortcut } from './CredentialShortcut'
import type { CredentialKeysApi } from '@/hooks/useCredentialKeys'

afterEach(() => cleanup())

function fakeKeys(overrides: Partial<CredentialKeysApi> = {}): CredentialKeysApi {
  return {
    loading: false,
    isSet: () => false,
    masked: () => '',
    save: vi.fn().mockResolvedValue(true),
    saving: null,
    error: '',
    refresh: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  }
}

const KEY = 'trufflehogGithubToken'
const LABEL = 'Secret Multiscanner GitHub Token'

describe('CredentialShortcut', () => {
  test('labels the key and says the value is global, not per-project', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    expect(screen.getByLabelText(LABEL)).toBeDefined()
    // Without this, an inline field inside a project form reads as a project
    // setting while it is in fact shared by every project the user owns.
    expect(screen.getByText('Global setting')).toBeDefined()
  })

  test('an unset mandatory key reads as Required', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    expect(screen.getByText('Required')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDefined()
  })

  test('an unset optional key reads as Optional, not Required', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} optional />)
    expect(screen.getByText('Optional')).toBeDefined()
    expect(screen.queryByText('Required')).toBeNull()
  })

  test('a stored secret is never put in the box, only offered as a placeholder', () => {
    const keys = fakeKeys({ isSet: () => true, masked: () => '••••••••cdef' })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    // Editable text would be sent back verbatim on the next save.
    expect(input.value).toBe('')
    expect(input.placeholder).toBe('••••••••cdef')
    expect(screen.getByText('Set')).toBeDefined()
    expect(screen.getByRole('button', { name: 'Replace' })).toBeDefined()
  })

  test('Save is inert until something is typed', () => {
    const keys = fakeKeys()
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const button = screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    fireEvent.change(screen.getByLabelText(LABEL), { target: { value: 'ghp_abc' } })
    expect(button.disabled).toBe(false)
  })

  test('whitespace alone does not enable Save', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    fireEvent.change(screen.getByLabelText(LABEL), { target: { value: '   ' } })
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true)
  })

  test('saving sends the trimmed value under the right settings key', async () => {
    const keys = fakeKeys()
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    fireEvent.change(screen.getByLabelText(LABEL), { target: { value: '  ghp_abc  ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(keys.save).toHaveBeenCalledWith(KEY, 'ghp_abc'))
  })

  test('Enter saves without submitting the surrounding form', async () => {
    const keys = fakeKeys()
    const onSubmit = vi.fn(e => e.preventDefault())
    render(
      <form onSubmit={onSubmit}>
        <CredentialShortcut settingsKey={KEY} keys={keys} />
      </form>,
    )
    const input = screen.getByLabelText(LABEL)
    fireEvent.change(input, { target: { value: 'ghp_abc' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(keys.save).toHaveBeenCalledWith(KEY, 'ghp_abc'))
    // The shortcut lives inside the project form; Enter must not save the project.
    expect(onSubmit).not.toHaveBeenCalled()
  })

  test('the box is cleared after a successful save', async () => {
    const keys = fakeKeys()
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    fireEvent.change(input, { target: { value: 'ghp_abc' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(input.value).toBe(''))
    expect(screen.getByText('Saved to Global Settings.')).toBeDefined()
  })

  test('a failed save leaves the typed value in place to retry', async () => {
    const keys = fakeKeys({ save: vi.fn().mockResolvedValue(false) })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    fireEvent.change(input, { target: { value: 'ghp_abc' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(keys.save).toHaveBeenCalled())
    expect(input.value).toBe('ghp_abc')
    expect(screen.queryByText('Saved to Global Settings.')).toBeNull()
  })

  test('a secret is typed behind a password field until revealed', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys()} />)
    const input = screen.getByLabelText(LABEL) as HTMLInputElement
    expect(input.type).toBe('password')
    fireEvent.click(screen.getByRole('button', { name: 'Show the value' }))
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).type).toBe('text')
  })

  test('a non-secret value has no reveal toggle and stays readable', () => {
    render(<CredentialShortcut settingsKey="githubEnterpriseHost" keys={fakeKeys()} />)
    const input = screen.getByLabelText('GitHub Enterprise Host') as HTMLInputElement
    // The host is the Supply Chain allowlist; masking it hides what is allowed.
    expect(input.type).toBe('text')
    expect(screen.queryByRole('button', { name: 'Show the value' })).toBeNull()
  })

  test('the input is disabled while its own save is in flight', () => {
    const keys = fakeKeys({ saving: KEY })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).disabled).toBe(true)
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDefined()
  })

  test('another key being saved does not disable this one', () => {
    const keys = fakeKeys({ saving: 'githubAccessToken' })
    render(<CredentialShortcut settingsKey={KEY} keys={keys} />)
    expect((screen.getByLabelText(LABEL) as HTMLInputElement).disabled).toBe(false)
  })

  test('compact drops the hint but keeps the control usable', () => {
    const { container } = render(
      <CredentialShortcut settingsKey={KEY} keys={fakeKeys()} compact />,
    )
    expect(container.textContent).not.toContain('unauthenticated GitHub allows only 60')
    expect(screen.getByLabelText(LABEL)).toBeDefined()
  })

  test('an unknown key renders nothing rather than an unlabelled box', () => {
    const { container } = render(
      <CredentialShortcut settingsKey="notARealKey" keys={fakeKeys()} />,
    )
    expect(container.innerHTML).toBe('')
  })

  test('a failed read says why, so an unset badge is not taken at its word', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys({ loadError: "Couldn't read your saved keys (P1001 · HTTP 500)" })} />)
    expect(screen.getByRole('alert').textContent)
      .toBe("Couldn't read your saved keys (P1001 · HTTP 500), so this key may already be set.")
  })

  test('a key that did load as set shows no read error', () => {
    render(<CredentialShortcut settingsKey={KEY} keys={fakeKeys({ isSet: () => true, loadError: 'stale' })} />)
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
