/**
 * Every limit a Rules of Engagement upload is held to, in one place, so the
 * routes that enforce them and the UI text that describes them cannot disagree.
 *
 * The file cap must stay under Next's request-body cap: every request through
 * middleware (which covers /api) is buffered up to
 * `experimental.proxyClientMaxBodySize` (60 MB in next.config.ts, the same as
 * nginx's client_max_body_size 60m), and a body over it is TRUNCATED rather than
 * refused (next/dist/server/body-streams.js). A limit above it would be
 * unreachable, and a truncated PDF fails as "corrupt" with no hint that size was
 * the cause. The 9 MB cap below sits well under it.
 */

export const MAX_FILE_SIZE = 9 * 1024 * 1024

/** The multipart envelope around a MAX_FILE_SIZE file, checked before parsing it. */
export const MAX_REQUEST_BYTES = Math.floor(9.5 * 1024 * 1024)

export const MAX_PDF_PAGES = 200

/** Extracted text kept from one document; the rest is dropped and reported. */
export const MAX_TEXT_CHARS = 2 * 1024 * 1024

/**
 * What the agent sends to the model (`agentic/api.py` `/roe/parse`). A longer
 * document is parsed from its first MAX_MODEL_CHARS characters only, which the
 * review says so the person knows the tail was never read.
 */
export const MAX_MODEL_CHARS = 50_000

/** A DOCX is a zip; these refuse a zip bomb before mammoth inflates it. */
export const MAX_DOCX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
export const MAX_DOCX_ENTRIES = 2_000

export const EXTRACT_TIMEOUT_MS = 30_000
export const EXTRACT_MAX_OLD_SPACE_MB = 256

export type RoeFileKind = 'pdf' | 'docx' | 'txt' | 'md'

const KINDS: Record<RoeFileKind, { ext: string; mimes: readonly string[]; contentType: string }> = {
  pdf: { ext: '.pdf', mimes: ['application/pdf'], contentType: 'application/pdf' },
  docx: {
    ext: '.docx',
    mimes: ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  },
  txt: { ext: '.txt', mimes: ['text/plain'], contentType: 'text/plain; charset=utf-8' },
  md: { ext: '.md', mimes: ['text/markdown', 'text/x-markdown'], contentType: 'text/markdown; charset=utf-8' },
}

/** The `accept` attribute for the file input. */
export const ACCEPT_ATTRIBUTE = Object.values(KINDS).map(k => k.ext).join(',')

export const ALLOWED_EXTENSIONS_LABEL = Object.values(KINDS).map(k => k.ext).join(', ')

/**
 * Which kind of document this is, or null when it is not one we read.
 *
 * The extension decides, because browsers send an empty or generic type for
 * `.md` and often for `.docx`. A declared type that names a DIFFERENT kind than
 * the extension is refused: the bytes would go to a parser chosen by one and
 * stored under a type chosen by the other.
 */
export function classifyRoeFile(name: string, mime: string): RoeFileKind | null {
  const lower = name.toLowerCase()
  const kind = (Object.keys(KINDS) as RoeFileKind[]).find(k => lower.endsWith(KINDS[k].ext))
  if (!kind) return null
  const declared = (mime || '').split(';')[0].trim().toLowerCase()
  if (declared && declared !== 'application/octet-stream' && !KINDS[kind].mimes.includes(declared)) {
    return null
  }
  return kind
}

/** The media type a stored document is stored and served under. */
export function canonicalMimeType(kind: RoeFileKind): string {
  return KINDS[kind].mimes[0]
}

/**
 * The Content-Type a stored document is served with: one of ours, or opaque
 * bytes. A stored type is client-supplied on legacy rows, and serving
 * `text/html` from it would turn a download into a page on our origin.
 */
export function downloadContentType(stored: string | null | undefined): string {
  const declared = (stored || '').split(';')[0].trim().toLowerCase()
  for (const k of Object.values(KINDS)) {
    if (k.mimes.includes(declared)) return k.contentType
  }
  return 'application/octet-stream'
}

/**
 * An RFC 6266 attachment header: an ASCII fallback for old clients plus the
 * UTF-8 name. The stored filename is client-supplied, so a quote, a CR/LF or a
 * semicolon in it must never reach the header unescaped.
 */
export function attachmentDisposition(fileName: string): string {
  const name = fileName.trim() || 'roe-document'
  const ascii = name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\;]/g, '_') || 'roe-document'
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeRfc5987(name)}`
}

function encodeRfc5987(value: string): string {
  return encodeURIComponent(value).replace(/['()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
}
