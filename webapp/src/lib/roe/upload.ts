/**
 * Read a RoE upload out of a multipart request, limits first.
 *
 * The Content-Length check runs BEFORE `request.formData()`, so an oversized
 * body is refused with its limit without being read. Past Next's request-body
 * cap (`experimental.proxyClientMaxBodySize`, 60 MB, the same as nginx's
 * client_max_body_size) a body arrives truncated rather than refused, and
 * parsing it would report a size problem as a corrupt file. A request without
 * the header (chunked) is read and then held to the same file cap.
 */
import { NextRequest, NextResponse } from 'next/server'

import {
  ALLOWED_EXTENSIONS_LABEL,
  MAX_FILE_SIZE,
  MAX_REQUEST_BYTES,
  classifyRoeFile,
  type RoeFileKind,
} from './limits'

export interface RoeUpload {
  formData: FormData
  file: File
  kind: RoeFileKind
  bytes: Buffer
}

const tooLarge = () =>
  NextResponse.json(
    { error: `The file is larger than ${MAX_FILE_SIZE / 1024 / 1024} MB.`, code: 'file_too_large', limitBytes: MAX_FILE_SIZE },
    { status: 413 },
  )

/**
 * Room for the multipart envelope (boundaries, part headers, small text fields)
 * on top of a file cap, so a file exactly at the cap is still accepted.
 */
export const MULTIPART_ENVELOPE_BYTES = 512 * 1024

function sizeLabel(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${Number((bytes / 1024 / 1024).toFixed(1))} MB`
  return `${Math.max(1, Math.round(bytes / 1024))} KB`
}

/**
 * The same check as `contentLengthProblem` for any multipart upload route: 413
 * `body_too_large` with the file cap when the declared body cannot hold a file
 * under `fileLimitBytes`, 400 for an unreadable header, else null. Run it before
 * `request.formData()`, so the person sees the limit; a body past Next's
 * request-body cap would otherwise fail as "Failed to parse body as FormData.".
 */
export function declaredBodyTooLarge(request: NextRequest, fileLimitBytes: number): NextResponse | null {
  const raw = request.headers.get('content-length')
  if (raw === null) return null
  const length = Number(raw)
  if (!Number.isFinite(length) || length < 0) {
    return NextResponse.json({ error: 'Invalid Content-Length.', code: 'invalid_content_length' }, { status: 400 })
  }
  if (length <= fileLimitBytes + MULTIPART_ENVELOPE_BYTES) return null
  return NextResponse.json(
    { error: `The upload is larger than ${sizeLabel(fileLimitBytes)}.`, code: 'body_too_large', limitBytes: fileLimitBytes },
    { status: 413 },
  )
}

/** 413 when the declared body is over the cap, otherwise null. */
export function contentLengthProblem(request: NextRequest): NextResponse | null {
  const raw = request.headers.get('content-length')
  if (raw === null) return null
  const length = Number(raw)
  if (!Number.isFinite(length) || length < 0) {
    return NextResponse.json({ error: 'Invalid Content-Length.' }, { status: 400 })
  }
  return length > MAX_REQUEST_BYTES ? tooLarge() : null
}

export async function readRoeUpload(
  request: NextRequest,
  fieldName = 'file',
): Promise<RoeUpload | NextResponse> {
  const lengthProblem = contentLengthProblem(request)
  if (lengthProblem) return lengthProblem

  let formData: FormData
  try {
    formData = await request.formData()
  } catch {
    return NextResponse.json({ error: 'The upload could not be read as multipart form data.', code: 'invalid_multipart' }, { status: 400 })
  }
  const file = formData.get(fieldName)
  if (!(file instanceof File)) {
    return NextResponse.json({ error: 'No file provided' }, { status: 400 })
  }
  if (file.size > MAX_FILE_SIZE) return tooLarge()
  const kind = classifyRoeFile(file.name, file.type)
  if (!kind) {
    return NextResponse.json(
      { error: `Unsupported file type. Use ${ALLOWED_EXTENSIONS_LABEL}.`, code: 'unsupported_type' },
      { status: 400 },
    )
  }
  return { formData, file, kind, bytes: Buffer.from(await file.arrayBuffer()) }
}
