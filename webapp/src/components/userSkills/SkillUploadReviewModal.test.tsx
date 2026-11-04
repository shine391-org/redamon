/**
 * The skill upload review dialog (single and batch): rows prefilled from each file, file
 * problems excluded with their reason, the batch name check and its suggestions, what blocks
 * Upload, the batch request and its outcomes (201, 409 refusal, 413, a lost answer), the
 * project's "Turn them on", the discard confirm, and no form submit leaking to a parent form.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within, act } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  requests: [] as { url: string; method: string; body: Record<string, unknown> | undefined }[],
  taken: new Set<string>(),
  batch: null as null | ((body: Record<string, unknown>) => Response | Promise<Response>),
  posted: [] as unknown[],
}))
vi.mock('@/lib/userSkillsChannel', async (orig) => ({
  ...(await orig<typeof import('@/lib/userSkillsChannel')>()),
  postUserSkillsChanged: (change: unknown) => void h.posted.push(change),
}))

import { SkillUploadReviewModal, type SkillUploadProject } from './SkillUploadReviewModal'
import type { PickedFile } from '@/lib/skillUploadDraft'
import { MAX_CONTENT_SIZE } from '@/lib/userSkills'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const key = (n: string) => n.normalize('NFC').replace(/\s+/g, ' ').trim().toLowerCase()

/** The batch name rule, enough for the dialog: stored names in `h.taken`, the later of two equal names a duplicate. */
function nameCheck(names: string[]) {
  const seen = new Set<string>()
  return names.map((name) => {
    const k = key(name)
    const reason = seen.has(k) ? 'name_duplicate' : h.taken.has(k) ? 'name_taken' : null
    seen.add(k)
    return reason
      ? { normalized: name.trim(), available: false, reason, suggestion: `${name.trim()} v2` }
      : { normalized: name.trim(), available: true, suggestion: null }
  })
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    h.requests.push({ url, method, body })
    if (url.endsWith('/name-check') && method === 'POST') return json(200, { results: nameCheck(body.names) })
    if (url.endsWith('/attack-skills/batch') && method === 'POST') {
      if (h.batch) return h.batch(body)
      return json(201, {
        created: body.items.map((i: { name: string }, n: number) => ({ id: `new${n}`, name: i.name })),
        enabled: body.enableInProjectId ? body.items.map((_: unknown, n: number) => `new${n}`) : [],
        leftOff: [],
      })
    }
    return json(404, {})
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  h.requests = []
  h.taken = new Set()
  h.batch = null
  h.posted = []
})

const FRONTMATTER: PickedFile = { name: 'f01_frontmatter.md', text: '---\nname: SQLi Flow\ndescription: >\n  Tests SQL\n  injection on example.com.\n---\n# Another title\n\nBody.' }
const HEADING: PickedFile = { name: 'f02_heading.md', text: '# Heading Only\n\nBody.' }
const PLAIN: PickedFile = { name: 'f03_plain.md', text: '## Phase 1\n\nBody.' }

function draw(files: PickedFile[], extra: Partial<Parameters<typeof SkillUploadReviewModal>[0]> = {}) {
  const props = {
    mode: 'batch' as const, userId: 'alice', existingCount: 0, files, cut: false,
    onClose: vi.fn(), onUploaded: vi.fn(), ...extra,
  }
  render(
    <ToastProvider>
      <AlertProvider>
        <SkillUploadReviewModal {...props} />
      </AlertProvider>
    </ToastProvider>,
  )
  return props
}

const nameField = (file: string) => screen.getByLabelText(`Name for ${file}`) as HTMLInputElement
const descriptionField = (file: string) => screen.getByLabelText(`Description for ${file}`) as HTMLTextAreaElement
const row = (file: string) => screen.getByTestId(`skill-upload-row-${file}`)
const uploadButton = () => screen.getByRole('button', { name: /^Upload( \d+ skills?)?$/ })
const checks = () => h.requests.filter((r) => r.url.endsWith('/name-check'))
const batches = () => h.requests.filter((r) => r.url.endsWith('/attack-skills/batch'))
const ready = () => waitFor(() => expect(uploadButton()).toBeEnabled())

describe('rows', () => {
  test('frontmatter, heading only and neither: prefilled as declared, the third empty; Use file name fills the stem', async () => {
    draw([FRONTMATTER, HEADING, PLAIN])
    expect(screen.getByRole('heading', { name: 'Upload 3 agent skills' })).toBeInTheDocument()
    expect(nameField('f01_frontmatter.md').value).toBe('SQLi Flow')
    expect(descriptionField('f01_frontmatter.md').value).toBe('Tests SQL injection on example.com.')
    expect(within(row('f01_frontmatter.md')).getAllByText('frontmatter')).toHaveLength(2)
    expect(nameField('f02_heading.md').value).toBe('Heading Only')
    expect(within(row('f02_heading.md')).getByText('heading')).toBeInTheDocument()
    expect(descriptionField('f02_heading.md').value).toBe('')
    expect(nameField('f03_plain.md').value).toBe('')
    expect(within(row('f03_plain.md')).getByText(/Needs a name/)).toBeInTheDocument()
    fireEvent.click(within(row('f03_plain.md')).getByRole('button', { name: 'Use file name' }))
    expect(nameField('f03_plain.md').value).toBe('f03_plain')
    expect(within(row('f03_plain.md')).getByText('file name')).toBeInTheDocument()
    expect(screen.getByTestId('skill-upload-summary').textContent).toMatch(/^3 files · \d ready/)
  })

  test('a file over MAX_CONTENT_SIZE and a .txt file are excluded with their reason; Upload counts only the valid rows', async () => {
    draw([HEADING, { name: 'huge.md', text: 'x'.repeat(MAX_CONTENT_SIZE + 1) }, { name: 'notes.txt', text: 'plain' }])
    expect(within(row('huge.md')).getByText("Larger than 500 KB: it can't be uploaded.")).toBeInTheDocument()
    expect(within(row('notes.txt')).getByText('Not a Markdown file.')).toBeInTheDocument()
    expect(screen.getByLabelText('Include huge.md')).toBeDisabled()
    expect(screen.getByLabelText('Include huge.md')).not.toBeChecked()
    await ready()
    expect(uploadButton()).toHaveTextContent('Upload 1 skill')
  })

  test('the preview is the first 60 lines as plain text, never rendered markdown', async () => {
    const lines = ['# Title', '<img src=x onerror=alert(1)>', '<script>alert(1)</script>', ...Array.from({ length: 80 }, (_, i) => `line ${i}`)]
    draw([{ name: 'p.md', text: lines.join('\n') }])
    fireEvent.click(within(row('p.md')).getByRole('button', { name: /Preview/ }))
    const pre = screen.getByTestId('skill-upload-preview-p.md')
    expect(pre.tagName).toBe('PRE')
    expect(pre.textContent).toBe(lines.slice(0, 60).join('\n'))
    expect(document.querySelector('[data-testid="skill-upload-review"] img, [data-testid="skill-upload-review"] script')).toBeNull()
  })
})

describe('the name check', () => {
  test('marks a taken name and "Use X v2" applies the suggestion', async () => {
    h.taken = new Set(['heading only'])
    draw([HEADING])
    expect(await within(row('f02_heading.md')).findByText('You already have a skill with this name.')).toBeInTheDocument()
    expect(uploadButton()).toBeDisabled()
    expect(uploadButton()).toHaveAttribute('title', '1 name is already used by your skills')
    fireEvent.click(within(row('f02_heading.md')).getByRole('button', { name: 'Use "Heading Only v2"' }))
    expect(nameField('f02_heading.md').value).toBe('Heading Only v2')
    await ready()
  })

  test('a duplicate inside the batch is marked on the later row', async () => {
    draw([HEADING, { name: 'f06_dup.md', text: '# heading   ONLY\n\nOther body.' }])
    expect(await within(row('f06_dup.md')).findByText('Another file in this upload has the same name.')).toBeInTheDocument()
    expect(within(row('f06_dup.md')).getByRole('button', { name: 'Use "heading ONLY v2"' })).toBeInTheDocument()
    expect(within(row('f02_heading.md')).queryByText(/same name/)).toBeNull()
  })

  test('editing a description starts no name check', async () => {
    draw([HEADING])
    await ready()
    const before = checks().length
    fireEvent.change(descriptionField('f02_heading.md'), { target: { value: 'A description' } })
    await new Promise((r) => setTimeout(r, 600))
    expect(checks()).toHaveLength(before)
  })
})

describe('Upload', () => {
  test('is disabled while a name is empty, and its title gives the reason', async () => {
    draw([HEADING, PLAIN])
    await waitFor(() => expect(checks().length).toBeGreaterThan(0))
    expect(uploadButton()).toBeDisabled()
    expect(uploadButton()).toHaveAttribute('title', '1 skill needs a name')
  })

  test('POSTs the included items in order; no enableInProjectId outside a project', async () => {
    draw([FRONTMATTER, PLAIN, HEADING])
    fireEvent.click(screen.getByLabelText('Include f03_plain.md'))
    fireEvent.change(descriptionField('f02_heading.md'), { target: { value: 'Line one\nline two' } })
    await ready()
    fireEvent.click(uploadButton())
    await waitFor(() => expect(batches()).toHaveLength(1))
    expect(batches()[0].body).toEqual({
      items: [
        { name: 'SQLi Flow', description: 'Tests SQL injection on example.com.', content: FRONTMATTER.text, nameSource: 'frontmatter', descriptionSource: 'frontmatter', aiModel: null },
        { name: 'Heading Only', description: 'Line one line two', content: HEADING.text, nameSource: 'heading', descriptionSource: 'typed', aiModel: null },
      ],
    })
  })

  test('with a saved project and the box checked it sends enableInProjectId; unchecked it does not', async () => {
    const project: SkillUploadProject = { id: 'p1', freeSlots: 7 }
    draw([HEADING], { project })
    expect(screen.getByLabelText(/Turn them on in this project/)).toBeChecked()
    expect(screen.getByText('(7 of 20 free)')).toBeInTheDocument()
    await ready()
    fireEvent.click(uploadButton())
    await waitFor(() => expect(batches()).toHaveLength(1))
    expect(batches()[0].body!.enableInProjectId).toBe('p1')
    cleanup()
    h.requests = []
    draw([HEADING], { project })
    fireEvent.click(screen.getByLabelText(/Turn them on in this project/))
    await ready()
    fireEvent.click(uploadButton())
    await waitFor(() => expect(batches()).toHaveLength(1))
    expect(batches()[0].body).not.toHaveProperty('enableInProjectId')
  })

  test('with no free slot the box is off and disabled, with the hint', () => {
    draw([HEADING], { project: { id: 'p1', freeSlots: 0 } })
    const box = screen.getByLabelText(/Turn them on in this project/)
    expect(box).toBeDisabled()
    expect(box).not.toBeChecked()
    expect(screen.getByText('This project already uses 20 of your skills')).toBeInTheDocument()
  })

  test('a body over 8 MB is never sent, and the banner names its size', async () => {
    // Control characters are escaped six bytes each in JSON: 30 legal files reach 9 MB.
    const files = Array.from({ length: 30 }, (_, i) => ({ name: `big${i}.md`, text: `# Big ${i}\n${'\u0001'.repeat(50_000)}` }))
    draw(files)
    await ready()
    fireEvent.click(uploadButton())
    expect(await screen.findByText(/^This batch is 8\.\d MB, above the 8 MB limit\. Remove some files, or upload them in smaller batches\.$/)).toBeInTheDocument()
    expect(batches()).toHaveLength(0)
  })

  test('a 409 batch_refused marks the right row, re-checks the names at once, and keeps the dialog open', async () => {
    h.batch = () => json(409, {
      code: 'batch_refused', error: '1 of 2 skills cannot be saved; nothing was saved.',
      items: [{ index: 1, code: 'name_taken', error: 'You already have a skill named "Heading Only".', suggestion: 'Heading Only v2' }],
    })
    const props = draw([FRONTMATTER, HEADING])
    await ready()
    const before = checks().length
    fireEvent.click(uploadButton())
    expect(await within(row('f02_heading.md')).findByText('You already have a skill named "Heading Only".')).toBeInTheDocument()
    expect(within(row('f01_frontmatter.md')).queryByText(/already have/)).toBeNull()
    expect(screen.getByText('Nothing was uploaded: fix the marked rows and try again.')).toBeInTheDocument()
    await waitFor(() => expect(checks().length).toBe(before + 1))
    expect(props.onClose).not.toHaveBeenCalled()
  })

  test('a 201 posts on the channel with the project id, calls onUploaded, says what was turned on, and closes', async () => {
    const props = draw([FRONTMATTER, HEADING], { project: { id: 'p1', freeSlots: 20 } })
    await ready()
    fireEvent.click(uploadButton())
    await waitFor(() => expect(props.onClose).toHaveBeenCalled())
    expect(h.posted).toEqual([{ projectId: 'p1' }])
    expect(props.onUploaded).toHaveBeenCalledWith({
      created: [{ id: 'new0', name: 'SQLi Flow' }, { id: 'new1', name: 'Heading Only' }], enabled: ['new0', 'new1'], leftOff: [],
    })
    expect(await screen.findByText('Uploaded 2 skills; 2 turned on for this project.')).toBeInTheDocument()
  })

  test('some left off, and a stored map that needs attention, each warn', async () => {
    h.batch = () => json(201, { created: [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }, { id: 'c', name: 'C' }], enabled: ['a'], leftOff: ['b', 'c'] })
    draw([FRONTMATTER, HEADING], { project: { id: 'p1', freeSlots: 1 } })
    await ready()
    fireEvent.click(uploadButton())
    expect(await screen.findByText('2 were left off: a project can use at most 20 of your skills.')).toBeInTheDocument()
    cleanup()
    h.batch = () => json(201, { created: [{ id: 'a', name: 'A' }], enabled: [], leftOff: [], enableSkipped: 'skill_quarantined' })
    draw([HEADING], { project: { id: 'p1', freeSlots: 3 } })
    await ready()
    fireEvent.click(uploadButton())
    expect(await screen.findByText(/The new skills were not turned on: this project's skill toggles need attention first/)).toBeInTheDocument()
  })

  test('outside a project the channel gets {} and the toast is plain', async () => {
    draw([FRONTMATTER, HEADING])
    await ready()
    fireEvent.click(uploadButton())
    expect(await screen.findByText('Uploaded 2 skills')).toBeInTheDocument()
    expect(h.posted).toEqual([{}])
  })

  test('create mode: enableLocally gets the created ids and its counts drive the summary', async () => {
    const enableLocally = vi.fn(() => ({ enabled: 1, leftOff: 1 }))
    draw([FRONTMATTER, HEADING], { project: { id: null, freeSlots: 1, enableLocally } })
    await ready()
    fireEvent.click(uploadButton())
    await waitFor(() => expect(enableLocally).toHaveBeenCalledWith(['new0', 'new1']))
    expect(batches()[0].body).not.toHaveProperty('enableInProjectId')
    expect(await screen.findByText('Uploaded 2 skills; 1 will be turned on when you create the project.')).toBeInTheDocument()
    expect(screen.getByText('1 was left off: a project can use at most 20 of your skills.')).toBeInTheDocument()
  })

  test('no answer, then every row is taken: the batch appears uploaded and only Close remains', async () => {
    h.batch = () => {
      h.taken = new Set(['sqli flow', 'heading only'])
      throw new TypeError('Failed to fetch')
    }
    const props = draw([FRONTMATTER, HEADING])
    await ready()
    fireEvent.click(uploadButton())
    expect(await screen.findByText('These skills appear to have been uploaded. Check your list.')).toBeInTheDocument()
    expect(h.posted).toEqual([{}])
    expect(screen.queryByRole('button', { name: 'Cancel' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    expect(props.onClose).toHaveBeenCalled()
  })

  test('no answer, and the names are still free: a warning, and the dialog stays', async () => {
    h.batch = () => { throw new TypeError('Failed to fetch') }
    const props = draw([HEADING])
    await ready()
    fireEvent.click(uploadButton())
    expect(await screen.findByText('The upload may not have finished. Check your skills list.')).toBeInTheDocument()
    expect(props.onClose).not.toHaveBeenCalled()
    expect(uploadButton()).toBeInTheDocument()
  })

  test('a 404 project_not_found keeps the dialog with a banner', async () => {
    h.batch = () => json(404, { code: 'project_not_found', error: 'That project is not yours.' })
    const props = draw([HEADING], { project: { id: 'gone', freeSlots: 5 } })
    await ready()
    fireEvent.click(uploadButton())
    expect(await screen.findByText('This project no longer exists; nothing was uploaded.')).toBeInTheDocument()
    expect(props.onClose).not.toHaveBeenCalled()
  })
})

describe('closing', () => {
  test('Cancel with untouched rows closes at once; with an edited row it asks first', async () => {
    let props = draw([HEADING])
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(props.onClose).toHaveBeenCalledTimes(1)
    cleanup()
    props = draw([HEADING, PLAIN])
    fireEvent.change(nameField('f03_plain.md'), { target: { value: 'Typed' } })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(await screen.findByText('Discard these 2 files? Nothing has been uploaded.')).toBeInTheDocument()
    expect(props.onClose).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }))
    await waitFor(() => expect(props.onClose).toHaveBeenCalledTimes(1))
  })

  test('nothing closes the dialog while the upload is in flight', async () => {
    let finish!: (r: Response) => void
    h.batch = () => new Promise<Response>((r) => { finish = r })
    const props = draw([HEADING])
    await ready()
    fireEvent.click(uploadButton())
    await waitFor(() => expect(batches()).toHaveLength(1))
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Close modal' }))
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' })
    expect(props.onClose).not.toHaveBeenCalled()
    await act(async () => { finish(json(201, { created: [{ id: 'x', name: 'Heading Only' }], enabled: [], leftOff: [] })) })
    await waitFor(() => expect(props.onClose).toHaveBeenCalledTimes(1))
  })
})

describe('inside a form', () => {
  test('Enter in a name field never submits a parent form, and no button is a submit', async () => {
    const onSubmit = vi.fn((e: React.FormEvent) => e.preventDefault())
    render(
      <ToastProvider>
        <AlertProvider>
          <form onSubmit={onSubmit}>
            <SkillUploadReviewModal mode="batch" userId="alice" existingCount={0} files={[HEADING]} cut={false} onClose={vi.fn()} />
          </form>
        </AlertProvider>
      </ToastProvider>,
    )
    fireEvent.keyDown(nameField('f02_heading.md'), { key: 'Enter', code: 'Enter' })
    fireEvent.keyPress(nameField('f02_heading.md'), { key: 'Enter', code: 'Enter', charCode: 13 })
    for (const b of within(screen.getByRole('dialog')).getAllByRole('button')) expect(b).toHaveAttribute('type', 'button')
    expect(screen.getByRole('dialog').querySelector('form')).toBeNull()
    expect(onSubmit).not.toHaveBeenCalled()
  })
})

describe('batch extras', () => {
  test('a banner when more files were picked than one batch holds', () => {
    draw([HEADING], { cut: true })
    expect(screen.getByText('Only the first 50 files were read; upload the rest in another batch.')).toBeInTheDocument()
  })

  test('a dropped file is added; the same file again is skipped; a drop never navigates', async () => {
    draw([HEADING])
    const zone = screen.getByTestId('skill-upload-review')
    const file = new File(['# Dropped skill\n\nBody.'], 'dropped.md', { type: 'text/markdown' })
    const over = new Event('dragover', { bubbles: true, cancelable: true })
    Object.assign(over, { dataTransfer: { types: ['Files'], dropEffect: 'none' } })
    zone.dispatchEvent(over)
    expect(over.defaultPrevented).toBe(true)
    const drop = (files: File[]) => {
      const e = new Event('drop', { bubbles: true, cancelable: true })
      Object.assign(e, { dataTransfer: { types: ['Files'], files } })
      zone.dispatchEvent(e)
      return e
    }
    const first = drop([file])
    expect(first.defaultPrevented).toBe(true)
    expect(await screen.findByLabelText('Name for dropped.md')).toHaveValue('Dropped skill')
    drop([new File(['# Heading Only\n\nBody.'], 'f02_heading.md')])
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.getAllByLabelText(/^Name for f02_heading\.md$/)).toHaveLength(1)
  })

  test('a file dropped outside the row area (the footer) never navigates the page either', () => {
    draw([HEADING])
    const cancel = screen.getByRole('button', { name: 'Cancel' })
    const fire = (type: 'dragover' | 'drop') => {
      const e = new Event(type, { bubbles: true, cancelable: true })
      Object.assign(e, { dataTransfer: { types: ['Files'], files: [], dropEffect: 'none' } })
      cancel.dispatchEvent(e)
      return e
    }
    expect(fire('dragover').defaultPrevented).toBe(true)
    expect(fire('drop').defaultPrevented).toBe(true)
  })

  test('Add files past 50 rows adds only up to 50 and shows the banner', async () => {
    draw(Array.from({ length: 49 }, (_, i) => ({ name: `r${i}.md`, text: `# Row ${i}\n` })))
    expect(screen.queryByText(/Only the first 50 files were read/)).toBeNull()
    const files = ['a', 'b', 'c'].map((n) => new File([`# Extra ${n}\n`], `extra-${n}.md`, { type: 'text/markdown' }))
    await act(async () => { fireEvent.change(screen.getByTestId('skill-upload-add-input'), { target: { files } }) })
    expect(await screen.findByText('Only the first 50 files were read; upload the rest in another batch.')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Upload 50 agent skills' })).toBeInTheDocument()
  })

  test('Remove drops a row', () => {
    draw([HEADING, PLAIN])
    fireEvent.click(screen.getByRole('button', { name: 'Remove f03_plain.md' }))
    expect(screen.queryByTestId('skill-upload-row-f03_plain.md')).toBeNull()
    expect(screen.getByRole('heading', { name: 'Upload 1 agent skill' })).toBeInTheDocument()
  })
})

describe('single mode', () => {
  test('no include box, no Remove, no Add files; the preview is open and the title is "Upload agent skill"', async () => {
    draw([PLAIN], { mode: 'single' })
    expect(screen.getByRole('heading', { name: 'Upload agent skill' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Include f03_plain.md')).toBeNull()
    expect(screen.queryByRole('button', { name: /Remove/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Add files/ })).toBeNull()
    expect(screen.getByTestId('skill-upload-preview-f03_plain.md')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Generate with AI$/ })).toBeInTheDocument()
    expect(nameField('f03_plain.md').value).toBe('')
    expect(descriptionField('f03_plain.md').rows).toBe(5)
  })
})
