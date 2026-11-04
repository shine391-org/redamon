'use client'

import { useCallback, useEffect, useMemo, useReducer, useRef, useState, type DragEvent } from 'react'
import { ChevronDown, ChevronRight, FilePlus, Loader2, Sparkles, Square, Trash2, Upload } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast } from '@/components/ui'
import { FeatureModelLine, useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { nameCheckMessage } from '@/components/settings/useSkillNameCheck'
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'
import { ApiError, formatApiError, readApiError, toApiError } from '@/lib/apiError'
import { cleanSkillText } from '@/lib/skillMetadata'
import {
  CREDENTIALS_ERROR, appendFiles, applyGenerated, applyNameChecks, applyRefusal, blockingReason, buildRows,
  failNameChecks, generationTargets, initialRoom, setDescription, setName, summarize, uploadPayload, withFileName,
  type BlockingReason, type DraftRow, type GeneratedItem, type PickedFile,
} from '@/lib/skillUploadDraft'
import {
  DESCRIPTION_MAX_CHARS, MAX_CONTENT_SIZE, MAX_ENABLED_USER_SKILLS_PER_PROJECT, MAX_SKILL_BATCH_BYTES, NAME_MAX_CHARS,
  SKILL_METADATA_ITEMS_PER_REQUEST, type BatchItemRefusal,
} from '@/lib/userSkills'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'
import { useBatchNameCheck, type BatchNameCheckOutcome } from './useBatchNameCheck'
import styles from './SkillUploadReviewModal.module.css'

export interface UploadedSkill { id: string; name: string }
export interface UploadResult { created: UploadedSkill[]; enabled: string[]; leftOff: string[]; enableSkipped?: string }

export interface SkillUploadProject {
  /** The saved project; null in the create-project form. */
  id: string | null
  /** A hint for the checkbox only: the batch route counts the room itself. */
  freeSlots: number
  /** Create mode only: put the ids in the form state; returns what fit. */
  enableLocally?: (ids: string[]) => { enabled: number; leftOff: number }
}

export const SKILL_FILE_ACCEPT = '.md,.markdown,text/markdown'

/** The picked files' text, read in parallel; a file the browser cannot read is marked, not dropped. */
export async function readPickedFiles(files: File[]): Promise<PickedFile[]> {
  return Promise.all(files.map(async (f) => {
    try {
      return { name: f.name, text: await f.text() }
    } catch {
      return { name: f.name, text: '', unreadable: true }
    }
  }))
}

const PREVIEW_LINES = 60

const PROBLEM_TEXT: Record<NonNullable<DraftRow['problem']>, string> = {
  not_markdown: 'Not a Markdown file.',
  empty: 'The file is empty.',
  not_text: 'Not a text file.',
  too_large: `Larger than ${MAX_CONTENT_SIZE / 1024} KB: it can't be uploaded.`,
  over_skill_limit: 'Over your 1,000-skill limit: delete some skills first.',
}

const SOURCE_TAG: Partial<Record<NonNullable<DraftRow['nameSource']>, string>> = {
  frontmatter: 'frontmatter', heading: 'heading', file: 'file name', ai: 'AI',
}

export const CREDENTIALS_TEXT = 'This file holds a key or token, so it was not sent to the model. Type the name and description.'
export const AI_FAILED_TEXT = 'The AI could not write this one. Type it, or try again.'
const CUT_TEXT = `Only the first 50 files were read; upload the rest in another batch.`
const REFUSED_TEXT = 'Nothing was uploaded: fix the marked rows and try again.'
const GONE_TEXT = 'This project no longer exists; nothing was uploaded.'
const COMMITTED_TEXT = 'These skills appear to have been uploaded. Check your list.'

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`
const sizeMb = (bytes: number) => (bytes / (1024 * 1024)).toFixed(1)
const tooLargeText = (bytes: number) =>
  `This batch is ${sizeMb(bytes)} MB, above the 8 MB limit. Remove some files, or upload them in smaller batches.`

function blockingTitle(reasons: BlockingReason[]): string | null {
  const count = (r: BlockingReason) => reasons.filter((x) => x === r).length
  if (count('name_missing')) return `${plural(count('name_missing'), 'skill needs', 'skills need')} a name`
  if (count('name_taken')) return `${plural(count('name_taken'), 'name is', 'names are')} already used by your skills`
  if (count('name_duplicate')) return `${plural(count('name_duplicate'), 'name is', 'names are')} used twice in this upload`
  if (count('name_invalid')) return `${plural(count('name_invalid'), 'name is', 'names are')} not valid`
  if (count('name_checking')) return 'Checking the names…'
  return null
}

type RowsUpdate = (rows: DraftRow[]) => DraftRow[]

interface Props {
  mode: 'single' | 'batch'
  userId: string
  existingCount: number
  files: PickedFile[]
  /** More files were picked than one batch holds. */
  cut: boolean
  project?: SkillUploadProject
  onUploaded?: (result: UploadResult) => void
  onClose: () => void
}

/**
 * The review of one upload, single or batch: every file with its name and description filled
 * in from the file when it declares them, editable, checked against the user's skills and the
 * rest of the batch, with Generate with AI for what is missing. Upload saves the batch whole or
 * not at all; in a project it can turn the new skills on, server-side in the same transaction.
 *
 * No `<form>` and only `type="button"`: rendered under the project form in React terms, a
 * submit would bubble to it through the portal.
 */
export function SkillUploadReviewModal({ mode, userId, existingCount, files, cut, project, onUploaded, onClose }: Props) {
  const { confirm, alertError } = useAlertModal()
  const toast = useToast()
  const { ensureFeatureModel, fetchWithFeatureModel } = useFeatureModelGate()
  const single = mode === 'single'
  const keyCounter = useRef(0)
  const nextKey = useCallback(() => `row-${++keyCounter.current}`, [])

  const [rows, dispatch] = useReducer(
    (state: DraftRow[], update: RowsUpdate) => update(state),
    undefined,
    () => buildRows(files, { room: initialRoom(existingCount), nextKey }),
  )
  const rowsRef = useRef(rows)
  rowsRef.current = rows

  const [uploading, setUploading] = useState(false)
  const [generating, setGenerating] = useState<{ done: number; total: number } | null>(null)
  const [banner, setBanner] = useState<string | null>(cut ? CUT_TEXT : null)
  const [committed, setCommitted] = useState(false)
  // Why the last name check failed; every row in the 'error' state shows it.
  const [nameCheckError, setNameCheckError] = useState<ApiError | null>(null)
  const [enableInProject, setEnableInProject] = useState(!!project && project.freeSlots > 0)
  const [previewOpen, setPreviewOpen] = useState<Record<string, boolean>>({})
  const stopRef = useRef<AbortController | null>(null)
  // Set before Generate's first await (the model lookup), which `generating` is not.
  const generateBusy = useRef(false)
  const addInput = useRef<HTMLInputElement>(null)

  // The drop zone covers only the rows: a file dropped on the header, the footer or the overlay
  // would otherwise make the browser open it in place of the page, losing every edit.
  useEffect(() => {
    const keep = (e: globalThis.DragEvent) => {
      if (e.dataTransfer?.types.includes('Files')) e.preventDefault()
    }
    window.addEventListener('dragover', keep)
    window.addEventListener('drop', keep)
    return () => {
      window.removeEventListener('dragover', keep)
      window.removeEventListener('drop', keep)
    }
  }, [])

  const update = useCallback((key: string, fn: (row: DraftRow) => DraftRow) => {
    dispatch((all) => all.map((r) => (r.key === key ? fn(r) : r)))
  }, [])

  const entries = useMemo(
    () => rows.filter((r) => r.include && !r.problem && r.name.trim()).map((r) => ({ key: r.key, name: r.name })),
    [rows],
  )
  const onCheck = useCallback((outcome: BatchNameCheckOutcome) => {
    if ('failed' in outcome) {
      setNameCheckError(outcome.error ?? null)
      dispatch((all) => failNameChecks(all, outcome.keys))
    } else {
      setNameCheckError(null)
      dispatch((all) => applyNameChecks(all, outcome.keys, outcome.results))
    }
  }, [])
  const { checkNow } = useBatchNameCheck(userId, entries, onCheck)

  const summary = summarize(rows)
  const reasons = rows.map(blockingReason).filter((r): r is BlockingReason => !!r)
  const targets = generationTargets(rows)
  const touched = rows.some((r) => r.touched)

  const uploadBlocked = !summary.included
    ? 'No file is included'
    : generating ? 'Wait for the AI to finish' : uploading ? 'Uploading…' : blockingTitle(reasons)

  const requestClose = useCallback(async () => {
    if (uploading) return
    if (!committed && touched) {
      const n = rowsRef.current.length
      const ok = await confirm(
        `Discard ${n === 1 ? 'this file' : `these ${n} files`}? Nothing has been uploaded.`,
        'Discard the upload?',
        { confirmLabel: 'Discard' },
      )
      if (!ok) return
    }
    stopRef.current?.abort()
    onClose()
  }, [uploading, committed, touched, confirm, onClose])

  const addFiles = useCallback(async (list: File[]) => {
    if (!list.length) return
    const picked = await readPickedFiles(list)
    // Read from the rows as they are now: the reducer itself runs later, during render.
    if (appendFiles(rowsRef.current, picked, { existingCount, nextKey: () => '' }).cut) setBanner(CUT_TEXT)
    dispatch((all) => appendFiles(all, picked, { existingCount, nextKey }).rows)
  }, [existingCount, nextKey])

  const onDragOver = useCallback((e: DragEvent) => {
    if (!e.dataTransfer.types.includes('Files')) return
    e.preventDefault()
    e.dataTransfer.dropEffect = single ? 'none' : 'copy'
  }, [single])
  const onDrop = useCallback((e: DragEvent) => {
    if (!e.dataTransfer.types.includes('Files')) return
    // Without this the browser opens the dropped file in place of the page.
    e.preventDefault()
    if (!single && !uploading) void addFiles(Array.from(e.dataTransfer.files ?? []))
  }, [single, uploading, addFiles])

  const generate = useCallback(async () => {
    if (!targets.length || generating || uploading || generateBusy.current) return
    generateBusy.current = true
    const model = await ensureFeatureModel('skill_metadata')
    if (!model) {
      generateBusy.current = false
      return
    }
    const stop = new AbortController()
    stopRef.current = stop
    const work = generationTargets(rowsRef.current)
    setBanner(null)
    try {
      for (let i = 0; i < work.length && !stop.signal.aborted; i += SKILL_METADATA_ITEMS_PER_REQUEST) {
        const chunk = work.slice(i, i + SKILL_METADATA_ITEMS_PER_REQUEST)
        setGenerating({ done: Math.min(i + chunk.length, work.length), total: work.length })
        const current = new Map(rowsRef.current.map((r) => [r.key, r]))
        const items = chunk.flatMap(({ key }) => {
          const r = current.get(key)
          // Re-read per request: a row the person excluded meanwhile is not sent.
          if (!r || !r.include || r.problem) return []
          const fields = [...(r.name.trim() ? [] : ['name']), ...(r.description.trim() ? [] : ['description'])]
          return fields.length ? [{ key, fileName: r.fileName, content: r.content, name: r.name.slice(0, NAME_MAX_CHARS), fields }] : []
        })
        if (!items.length) continue
        const asked = new Set(items.map((x) => x.key))
        const otherNames = rowsRef.current
          .filter((r) => r.include && !r.problem && r.name.trim() && !asked.has(r.key))
          .map((r) => r.name.slice(0, NAME_MAX_CHARS))
          .slice(0, 50)
        const res = await fetchWithFeatureModel('skill_metadata', () => fetch(`/api/users/${userId}/attack-skills/generate-metadata`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ items, otherNames }),
          signal: stop.signal,
        }))
        if (!res.ok) {
          const err = await readApiError(res, 'The AI could not write the missing fields')
          const code = readFeatureModelCode(err.body)
          setBanner(code ? featureModelMessage(code, model) : err.message)
          break
        }
        const body = await res.json().catch(() => ({}))
        const answers: GeneratedItem[] = Array.isArray(body.items) ? body.items : []
        dispatch((all) => applyGenerated(all, answers, typeof body.modelUsed === 'string' ? body.modelUsed : null))
      }
    } catch (e) {
      if (!stop.signal.aborted) setBanner(toApiError(e, 'The AI could not be reached. Try again in a moment.').message)
    } finally {
      stopRef.current = null
      generateBusy.current = false
      setGenerating(null)
      void checkNow()
    }
  }, [targets.length, generating, uploading, ensureFeatureModel, fetchWithFeatureModel, userId, checkNow])

  const summaryToasts = useCallback((result: UploadResult) => {
    const n = result.created.length
    const head = single && n === 1 ? 'Skill uploaded' : `Uploaded ${plural(n, 'skill', 'skills')}`
    if (project && enableInProject && project.id) {
      toast.success(result.enabled.length ? `${head}; ${result.enabled.length} turned on for this project.` : `${head}.`)
      if (result.leftOff.length) {
        toast.warning(`${plural(result.leftOff.length, 'was', 'were')} left off: a project can use at most ${MAX_ENABLED_USER_SKILLS_PER_PROJECT} of your skills.`)
      }
      if (result.enableSkipped) {
        toast.warning("The new skills were not turned on: this project's skill toggles need attention first. Open its Agent Skills settings.")
      }
      return
    }
    if (project && enableInProject && project.enableLocally) {
      const local = project.enableLocally(result.created.map((s) => s.id))
      toast.success(local.enabled ? `${head}; ${local.enabled} will be turned on when you create the project.` : `${head}.`)
      if (local.leftOff) {
        toast.warning(`${plural(local.leftOff, 'was', 'were')} left off: a project can use at most ${MAX_ENABLED_USER_SKILLS_PER_PROJECT} of your skills.`)
      }
      return
    }
    toast.success(head)
  }, [single, project, enableInProject, toast])

  const upload = useCallback(async () => {
    if (uploadBlocked) return
    const { keys, items } = uploadPayload(rowsRef.current)
    const enableInProjectId = project?.id && enableInProject ? project.id : undefined
    const body = JSON.stringify({ items, ...(enableInProjectId ? { enableInProjectId } : {}) })
    const bytes = new TextEncoder().encode(body).length
    if (bytes > MAX_SKILL_BATCH_BYTES) {
      setBanner(tooLargeText(bytes))
      return
    }
    setUploading(true)
    setBanner(null)
    let res: Response
    try {
      res = await fetch(`/api/users/${userId}/attack-skills/batch`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
      })
    } catch {
      // No answer: the batch may have committed. Every open list shows what landed, and a
      // name check that finds every name taken means it did.
      postUserSkillsChanged({})
      const results = await checkNow()
      setUploading(false)
      if (results && results.length === keys.length && results.every((r) => r.reason === 'name_taken')) {
        setCommitted(true)
        setBanner(COMMITTED_TEXT)
      } else {
        toast.warning('The upload may not have finished. Check your skills list.')
      }
      return
    }
    const answer = await res.json().catch(() => ({}))
    setUploading(false)
    if (res.status === 201) {
      const result: UploadResult = {
        created: Array.isArray(answer.created)
          ? answer.created.map((s: { id: string; name: string }) => ({ id: s.id, name: s.name }))
          : [],
        enabled: Array.isArray(answer.enabled) ? answer.enabled : [],
        leftOff: Array.isArray(answer.leftOff) ? answer.leftOff : [],
        ...(typeof answer.enableSkipped === 'string' ? { enableSkipped: answer.enableSkipped } : {}),
      }
      postUserSkillsChanged(project?.id ? { projectId: project.id } : {})
      summaryToasts(result)
      onUploaded?.(result)
      onClose()
      return
    }
    if (res.status === 409 && answer.code === 'batch_refused') {
      dispatch((all) => applyRefusal(all, keys, Array.isArray(answer.items) ? answer.items as BatchItemRefusal[] : []))
      setBanner(REFUSED_TEXT)
      void checkNow()
      return
    }
    if (res.status === 413) {
      setBanner(tooLargeText(bytes))
      return
    }
    if (res.status === 404 && answer.code === 'project_not_found') {
      setBanner(GONE_TEXT)
      return
    }
    void alertError(formatApiError({
      reason: (typeof answer.error === 'string' && answer.error) || 'Failed to upload the skills',
      code: typeof answer.code === 'string' ? answer.code : undefined,
      status: res.status,
    }))
  }, [uploadBlocked, project, enableInProject, userId, checkNow, toast, summaryToasts, onUploaded, onClose, alertError])

  const title = single ? 'Upload agent skill' : `Upload ${plural(rows.length, 'agent skill', 'agent skills')}`

  const footer = committed ? (
    <button type="button" className="primaryButton" onClick={onClose}>Close</button>
  ) : (
    <div className={styles.footer}>
      {project && (
        <label className={styles.enableCheck} title={project.freeSlots === 0 ? 'This project already uses 20 of your skills' : undefined}>
          <input
            type="checkbox"
            checked={enableInProject}
            disabled={project.freeSlots === 0 || uploading}
            onChange={(e) => setEnableInProject(e.target.checked)}
          />
          {single ? 'Turn it on in this project' : 'Turn them on in this project'}
          <span className={styles.muted}>({project.freeSlots} of {MAX_ENABLED_USER_SKILLS_PER_PROJECT} free)</span>
          {project.freeSlots === 0 && <span className={styles.muted}>This project already uses 20 of your skills</span>}
        </label>
      )}
      <div className={styles.footerButtons}>
        <button type="button" className="secondaryButton" onClick={() => void requestClose()} disabled={uploading}>Cancel</button>
        <button
          type="button"
          className="primaryButton"
          onClick={() => void upload()}
          disabled={!!uploadBlocked}
          title={uploadBlocked ?? undefined}
        >
          {uploading ? <Loader2 size={14} className={styles.spin} /> : <Upload size={14} />}
          {single ? 'Upload' : `Upload ${plural(summary.included, 'skill', 'skills')}`}
        </button>
      </div>
    </div>
  )

  return (
    <Modal
      isOpen
      onClose={() => void requestClose()}
      title={title}
      size={single ? 'large' : 'xlarge'}
      closeOnOverlayClick={false}
      closeOnEscape={!uploading}
      footer={footer}
    >
      <div className={styles.dropZone} onDragOver={onDragOver} onDrop={onDrop} data-testid="skill-upload-review">
        {!single && (
          <div className={styles.summaryRow}>
            <span className={styles.summary} data-testid="skill-upload-summary">
              {[
                plural(summary.total, 'file', 'files'),
                `${summary.ready} ready`,
                summary.needName ? `${summary.needName} ${summary.needName === 1 ? 'needs' : 'need'} a name` : '',
                summary.noDescription ? `${summary.noDescription} without a description` : '',
                summary.problems ? `${summary.problems} can't be uploaded` : '',
              ].filter(Boolean).join(' · ')}
            </span>
            <button
              type="button"
              className="secondaryButton"
              onClick={() => addInput.current?.click()}
              disabled={uploading || committed || rows.length >= 50}
            >
              <FilePlus size={14} /> Add files
            </button>
            <input
              ref={addInput}
              type="file"
              multiple
              accept={SKILL_FILE_ACCEPT}
              style={{ display: 'none' }}
              data-testid="skill-upload-add-input"
              onChange={(e) => {
                const list = Array.from(e.target.files ?? [])
                e.target.value = ''
                void addFiles(list)
              }}
            />
          </div>
        )}

        {!committed && (
          <div className={styles.aiBar}>
            <div className={styles.aiRow}>
              <button
                type="button"
                className="secondaryButton aiGenerateButton"
                onClick={() => void generate()}
                disabled={!targets.length || !!generating || uploading}
                title={!targets.length ? 'Every name and description is filled' : undefined}
              >
                <Sparkles size={14} /> {single ? 'Generate with AI' : 'Generate missing with AI'}
              </button>
              <FeatureModelLine featureId="skill_metadata" />
              {generating && (
                <button type="button" className="secondaryButton" onClick={() => stopRef.current?.abort()}>
                  <Square size={12} /> Stop
                </button>
              )}
            </div>
            <p className={styles.muted}>
              Fills only the empty names and descriptions. Check them before uploading.
              {' '}Files that contain a key or token are not sent to the model.
            </p>
          </div>
        )}

        <div className={styles.live} role="status" aria-live="polite">
          {generating && <span><Loader2 size={12} className={styles.spin} /> Writing {generating.done} of {generating.total}…</span>}
          {banner && <span className={styles.banner}>{banner}</span>}
        </div>

        <div className={styles.rows}>
          {rows.map((row) => (
            <RowView
              key={row.key}
              row={row}
              single={single}
              busy={uploading || committed}
              nameCheckError={nameCheckError}
              previewOpen={previewOpen[row.key] ?? single}
              onTogglePreview={() => setPreviewOpen((p) => ({ ...p, [row.key]: !(p[row.key] ?? single) }))}
              onInclude={(include) => update(row.key, (r) => ({
                ...r, include, nameCheck: include && r.name.trim() ? { state: 'checking', suggestion: null, reason: null } : r.nameCheck,
              }))}
              onRemove={() => dispatch((all) => all.filter((r) => r.key !== row.key))}
              onName={(name, source) => update(row.key, (r) => setName(r, name, source))}
              onFileName={() => update(row.key, withFileName)}
              onDescription={(d) => update(row.key, (r) => setDescription(r, d))}
            />
          ))}
        </div>
      </div>
    </Modal>
  )
}

function RowView({
  row, single, busy, nameCheckError, previewOpen, onTogglePreview, onInclude, onRemove, onName, onFileName, onDescription,
}: {
  row: DraftRow
  single: boolean
  busy: boolean
  nameCheckError: ApiError | null
  previewOpen: boolean
  onTogglePreview: () => void
  onInclude: (include: boolean) => void
  onRemove: () => void
  onName: (name: string, source?: 'typed') => void
  onFileName: () => void
  onDescription: (description: string) => void
}) {
  const ids = {
    name: `${row.key}-name-status`,
    description: `${row.key}-description-status`,
  }
  const kb = Math.max(1, Math.round(row.chars / 1024))
  const nameTag = row.nameSource ? SOURCE_TAG[row.nameSource] : undefined
  const descriptionTag = row.descriptionSource ? SOURCE_TAG[row.descriptionSource] : undefined
  const suggestion = row.serverError?.suggestion ?? (row.nameCheck.state === 'taken' || row.nameCheck.state === 'duplicate'
    ? row.nameCheck.suggestion : null)
  const counted = cleanSkillText(row.description).length

  const nameStatus: React.ReactNode[] = []
  if (row.serverError) nameStatus.push(<span key="server" className={styles.error}>{row.serverError.error}</span>)
  if (row.aiError) {
    nameStatus.push(<span key="ai" className={styles.warn}>{row.aiError === CREDENTIALS_ERROR ? CREDENTIALS_TEXT : AI_FAILED_TEXT}</span>)
  }
  if (!row.name.trim()) {
    nameStatus.push(
      <span key="missing" className={styles.warn}>
        Needs a name ·{' '}
        <button type="button" className={styles.link} onClick={onFileName} disabled={busy}>Use file name</button>
      </span>,
    )
  } else if (!row.serverError) {
    const check = row.nameCheck
    // The suggestion is its own button below, so the message is asked without it.
    const text = check.state === 'duplicate'
      ? 'Another file in this upload has the same name.'
      : nameCheckMessage({ state: check.state, suggestion: null, reason: check.reason, error: nameCheckError })
    if (text) nameStatus.push(<span key="check" className={check.state === 'error' ? styles.muted : styles.warn}>{text}</span>)
  }
  if (suggestion) {
    nameStatus.push(
      <button key="suggest" type="button" className={styles.link} onClick={() => onName(suggestion)} disabled={busy}>
        Use &quot;{suggestion}&quot;
      </button>,
    )
  }
  if (row.nameShortened) nameStatus.push(<span key="short" className={styles.muted}>Shortened to {NAME_MAX_CHARS} characters</span>)

  return (
    <div className={`${styles.row} ${row.problem ? styles.rowProblem : ''}`} data-testid={`skill-upload-row-${row.fileName}`}>
      <div className={styles.fileLine}>
        {!single && (
          <input
            type="checkbox"
            checked={row.include}
            disabled={!!row.problem || busy}
            onChange={(e) => onInclude(e.target.checked)}
            aria-label={`Include ${row.fileName}`}
          />
        )}
        <span className={styles.fileName}>{row.fileName}</span>
        <span className={styles.muted}>· {kb} KB</span>
        {row.problem && <span className={styles.error}>{PROBLEM_TEXT[row.problem]}</span>}
        <span className={styles.fileActions}>
          {!row.problem && (
            <button type="button" className={styles.link} onClick={onTogglePreview} aria-expanded={previewOpen}>
              {previewOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />} Preview
            </button>
          )}
          {!single && (
            <button type="button" className="iconButton" onClick={onRemove} disabled={busy} title={`Remove ${row.fileName}`} aria-label={`Remove ${row.fileName}`}>
              <Trash2 size={14} />
            </button>
          )}
        </span>
      </div>

      {!row.problem && previewOpen && (
        // Text only: the file is untrusted, so its markdown is never rendered.
        <pre className={styles.preview} data-testid={`skill-upload-preview-${row.fileName}`}>
          {row.content.split(/\r?\n/).slice(0, PREVIEW_LINES).join('\n')}
        </pre>
      )}

      {!row.problem && (
        <div className={styles.fields}>
          <label className={styles.fieldLabel} htmlFor={`${row.key}-name`}>Name</label>
          <div className={styles.field}>
            <div className={styles.inputRow}>
              <input
                id={`${row.key}-name`}
                className="textInput"
                type="text"
                value={row.name}
                maxLength={NAME_MAX_CHARS}
                disabled={!row.include || busy}
                onChange={(e) => onName(e.target.value)}
                aria-label={`Name for ${row.fileName}`}
                aria-describedby={nameStatus.length ? ids.name : undefined}
              />
              {nameTag && <span className={styles.tag}>{nameTag}</span>}
            </div>
            {nameStatus.length > 0 && <div id={ids.name} className={styles.status}>{nameStatus}</div>}
          </div>

          <label className={styles.fieldLabel} htmlFor={`${row.key}-description`}>Description</label>
          <div className={styles.field}>
            <div className={styles.inputRow}>
              <textarea
                id={`${row.key}-description`}
                className="textInput"
                rows={single ? 5 : 2}
                value={row.description}
                maxLength={DESCRIPTION_MAX_CHARS}
                disabled={!row.include || busy}
                onChange={(e) => onDescription(e.target.value)}
                aria-label={`Description for ${row.fileName}`}
                aria-describedby={ids.description}
              />
              {descriptionTag && <span className={styles.tag}>{descriptionTag}</span>}
            </div>
            <div id={ids.description} className={styles.status}>
              {row.descriptionShortened && <span className={styles.muted}>Shortened to {DESCRIPTION_MAX_CHARS} characters</span>}
              {!row.description.trim() && (
                <span className={styles.muted}>Optional. Without one the agent reads the first 500 characters of the skill.</span>
              )}
              <span className={styles.counter}>{counted} / {DESCRIPTION_MAX_CHARS}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
