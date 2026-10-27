/** @vitest-environment node */
/**
 * Every webapp route the Python services call is on the middleware's key
 * allowlist (drift-map #19), computed from the Python source rather than copied.
 *
 * Python services hold no session, so each webapp call they make passes the
 * middleware only through X-Internal-Key (the internal key, or the scoped scanner
 * key sent in the same header). A route missing from INTERNAL_ALLOWLIST is let
 * through with a log line today and refused the day INTERNAL_KEY_ALLOWLIST_ENFORCE
 * is switched on; one missing from SCANNER_ALLOWLIST is refused already.
 *
 * The call sites are read from the source of agentic/, recon/, recon_orchestrator/,
 * graph_db/, mcp/, scanners/ and services/ (tests excluded): every f-string that
 * starts with a webapp base (`{WEBAPP_API_URL}`, `{webapp_url.rstrip('/')}`, a
 * name assigned from one, or a module constant holding a webapp URL) followed by
 * `/api/`. Its placeholders become one path segment each and the query string is
 * dropped. The method comes from the call that uses the URL: `client.post(...)`,
 * a `method=` or positional "POST" argument, urllib's `Request` (POST with
 * `data=`), or the helper the URL is handed to (its `method="GET"` default, or the
 * Request it builds), following `url = ...` to its uses and `asyncio.to_thread`
 * to the function it runs. A site the extractor cannot read fails the test until
 * it is listed in UNPARSED_CALL_SITES with the routes it calls.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { describe, test, expect } from 'vitest'
import { internalKeyRouteAllowed, scannerKeyRouteAllowed } from './middleware'

const REPO = join(__dirname, '..', '..')
const PY_ROOTS = ['agentic', 'recon', 'recon_orchestrator', 'graph_db', 'mcp', 'scanners', 'services']
const available = PY_ROOTS.every(r => existsSync(join(REPO, r)))

/**
 * Call sites whose URL is completed somewhere the extractor does not follow.
 * Matched by file and the URL literal as written; `calls` are checked against
 * the middleware like any extracted route.
 */
const UNPARSED_CALL_SITES: { at: string; literal: string; why: string; calls: [string, string][] }[] = [
  {
    at: 'agentic/node_filter_runs.py:116',
    literal: '{WEBAPP_API_URL}/api/internal/node-filter-runs/{self.run_id}{suffix}',
    why: '_url(suffix) is completed by its callers: fetch() GETs it bare, heartbeat() and finish() POST it with "/heartbeat" and "/finish"',
    calls: [
      ['GET', '/api/internal/node-filter-runs/x'],
      ['POST', '/api/internal/node-filter-runs/x/heartbeat'],
      ['POST', '/api/internal/node-filter-runs/x/finish'],
    ],
  },
]

/**
 * `{base}/api/...` f-strings in a file that sends the internal key, whose base is
 * not the webapp. Listed so a webapp base under an unfamiliar name cannot pass
 * as some other service.
 */
const NOT_THE_WEBAPP: { file: string; base: string; why: string }[] = []

// ---------------------------------------------------------------------------
// A Python tokenizer: just enough to find string literals, names, brackets and
// logical lines (with their indentation) without being fooled by comments or
// by quotes inside strings.
// ---------------------------------------------------------------------------

type Tok = { t: 'name' | 'str' | 'op' | 'num' | 'nl'; v: string; line: number; indent: number; f?: boolean }

const IDENT = /[A-Za-z0-9_\u0080-\uffff]/
const STRING_PREFIX = /^(?:[rRbBuUfF]|[rR][bBfF]|[bBfF][rR])$/

function tokenize(src: string): Tok[] {
  const toks: Tok[] = []
  const n = src.length
  let i = 0
  let line = 1
  let depth = 0
  let indent = 0
  let lineStart = true
  const push = (t: Tok['t'], v: string, extra: Partial<Tok> = {}) => toks.push({ t, v, line, indent, ...extra })

  const readString = (prefix: string) => {
    const q = src[i]
    const term = src.startsWith(q.repeat(3), i) ? q.repeat(3) : q
    const startLine = line
    let j = i + term.length
    let body = ''
    while (j < n && !src.startsWith(term, j)) {
      if (src[j] === '\\') {
        if (src[j + 1] === '\n') line++
        body += src.slice(j, j + 2)
        j += 2
        continue
      }
      if (src[j] === '\n') {
        line++
        if (term.length === 1) break
      }
      body += src[j]
      j++
    }
    toks.push({ t: 'str', v: body, line: startLine, indent, f: /f/i.test(prefix) })
    i = j + term.length
  }

  while (i < n) {
    if (lineStart && depth === 0) {
      let w = 0
      let j = i
      while (j < n && (src[j] === ' ' || src[j] === '\t')) {
        w += src[j] === '\t' ? 8 - (w % 8) : 1
        j++
      }
      if (j < n && src[j] !== '\n' && src[j] !== '\r' && src[j] !== '#') indent = w
      i = j
      lineStart = false
      continue
    }
    const c = src[i]
    if (c === '\n') {
      if (depth === 0) {
        if (toks.length && toks[toks.length - 1].t !== 'nl') push('nl', '')
        lineStart = true
      }
      line++
      i++
      continue
    }
    if (c === ' ' || c === '\t' || c === '\r' || c === '\f') { i++; continue }
    if (c === '\\' && src[i + 1] === '\n') { i += 2; line++; continue }
    if (c === '#') {
      while (i < n && src[i] !== '\n') i++
      continue
    }
    if (c === '"' || c === "'") { readString(''); continue }
    if (/[0-9]/.test(c)) {
      let j = i
      while (j < n && /[\w.]/.test(src[j])) j++
      push('num', src.slice(i, j))
      i = j
      continue
    }
    if (IDENT.test(c)) {
      let j = i
      while (j < n && IDENT.test(src[j])) j++
      const word = src.slice(i, j)
      i = j
      if (STRING_PREFIX.test(word) && (src[i] === '"' || src[i] === "'")) { readString(word); continue }
      push('name', word)
      continue
    }
    if ('([{'.includes(c)) depth++
    if (')]}'.includes(c)) depth = Math.max(0, depth - 1)
    push('op', c)
    i++
  }
  return toks
}

// ---------------------------------------------------------------------------
// Source model
// ---------------------------------------------------------------------------

type StrExpr = { text: string; f: boolean; line: number; s: number; e: number }
type PyFile = { rel: string; src: string; toks: Tok[]; strs: StrExpr[]; keyed: boolean; scannerFirst: boolean }

const SKIP_DIRS = new Set(['tests', 'tests_live', 'node_modules', '__pycache__', '.venv', 'venv', 'site-packages'])

function pythonFiles(dir: string): string[] {
  const out: string[] = []
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) out.push(...pythonFiles(join(dir, e.name)))
    } else if (
      e.name.endsWith('.py') && !e.name.startsWith('test_') && !e.name.endsWith('_test.py') && e.name !== 'conftest.py'
    ) {
      out.push(join(dir, e.name))
    }
  }
  return out
}

function joinStrings(toks: Tok[]): StrExpr[] {
  const out: StrExpr[] = []
  for (let k = 0; k < toks.length; k++) {
    if (toks[k].t !== 'str') continue
    let e = k
    while (toks[e + 1]?.t === 'str') e++
    const parts = toks.slice(k, e + 1)
    out.push({ text: parts.map(p => p.v).join(''), f: parts.some(p => p.f), line: toks[k].line, s: k, e })
    k = e
  }
  return out
}

function parseFile(rel: string, src: string): PyFile {
  const toks = tokenize(src)
  return {
    rel,
    src,
    toks,
    strs: joinStrings(toks),
    keyed: /x-internal-key|INTERNAL_HEADERS|from webapp_client import/i.test(src),
    // `os.environ.get("SCANNER_API_KEY") or ...`: the scan-container header, which
    // falls back to the internal key only on installs that predate the scanner key.
    scannerFirst: toks.some((t, k) => t.t === 'str' && t.v === 'SCANNER_API_KEY'
      && isOp(toks[k + 1], ')') && isName(toks[k + 2], 'or')),
  }
}

function loadRepoFiles(): PyFile[] {
  return PY_ROOTS.flatMap(r => pythonFiles(join(REPO, r)))
    .map(abs => parseFile(relative(REPO, abs).split(sep).join('/'), readFileSync(abs, 'utf8')))
}

const isStmtStart = (toks: Tok[], k: number) => k === 0 || toks[k - 1].t === 'nl'
const isOp = (tok: Tok | undefined, v: string) => tok?.t === 'op' && tok.v === v
const isName = (tok: Tok | undefined, v?: string) => tok?.t === 'name' && (v === undefined || tok.v === v)

/** `a = rhs` / `a, b = rhs` statements: target name -> RHS token ranges. */
function assignments(toks: Tok[]): Map<string, { at: number; rhs: [number, number] }[]> {
  const out = new Map<string, { at: number; rhs: [number, number] }[]>()
  for (let k = 0; k < toks.length; k++) {
    if (!isStmtStart(toks, k) || !isName(toks[k])) continue
    const targets: string[] = []
    let j = k
    while (isName(toks[j])) {
      targets.push(toks[j].v)
      if (isOp(toks[j + 1], ',')) j += 2
      else { j++; break }
    }
    if (!isOp(toks[j], '=') || isOp(toks[j + 1], '=')) continue
    let end = j + 1
    while (end < toks.length && toks[end].t !== 'nl') end++
    for (const name of targets) {
      if (!out.has(name)) out.set(name, [])
      out.get(name)!.push({ at: k, rhs: [j + 1, end] })
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// Which strings are webapp URLs
// ---------------------------------------------------------------------------

const LEADING_PLACEHOLDER = /^\{([^{}]*)\}/
const ABSOLUTE_WEBAPP = /^https?:\/\/webapp(?::\d+)?(\/api\/.*)$/

type UrlSite = { file: PyFile; str: StrExpr; path: string }

function webappSites(file: PyFile, others: { file: string; base: string; line: number }[]): UrlSite[] {
  const assigned = assignments(file.toks)
  const rhsText = (r: [number, number]) => file.toks.slice(r[0], r[1]).map(t => t.v).join(' ')
  const isWebappBase = (expr: string) =>
    /webapp/i.test(expr)
    || (/^\w+$/.test(expr) && (assigned.get(expr) ?? []).some(a => /webapp/i.test(rhsText(a.rhs))))

  // Names assigned a webapp URL, then extended as `{_BASE}/{job_id}/start`.
  const prefixes = new Map<string, string>()
  const sites: UrlSite[] = []
  for (const str of file.strs) {
    const abs = !str.f && ABSOLUTE_WEBAPP.exec(str.text)
    if (abs) {
      sites.push({ file, str, path: abs[1] })
      continue
    }
    if (!str.f) continue
    const m = LEADING_PLACEHOLDER.exec(str.text)
    if (!m) continue
    const base = m[1].trim()
    const rest = str.text.slice(m[0].length)
    if (!rest.startsWith('/api/')) continue
    if (isWebappBase(base)) {
      sites.push({ file, str, path: rest })
      const at = file.toks[str.s - 1]
      if (isOp(at, '=') && isName(file.toks[str.s - 2]) && isStmtStart(file.toks, str.s - 2)) {
        prefixes.set(file.toks[str.s - 2].v, rest)
      }
    } else if (file.keyed) {
      others.push({ file: file.rel, base, line: str.line })
    }
  }
  for (const str of file.strs) {
    if (!str.f) continue
    const m = LEADING_PLACEHOLDER.exec(str.text)
    const prefix = m ? prefixes.get(m[1].trim()) : undefined
    const tail = m ? str.text.slice(m[0].length) : ''
    if (prefix !== undefined && tail.startsWith('/')) sites.push({ file, str, path: prefix + tail })
  }
  return sites
}

// ---------------------------------------------------------------------------
// The method a URL is requested with
// ---------------------------------------------------------------------------

const VERBS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
const NOT_A_REQUEST = new Set(['logger', 'logging', 'print', 'str', 'len', 'repr', 'format'])

type Call = { open: number; close: number; chain: string[]; args: [number, number][] }

/** The call whose argument list holds token k directly, if any. */
function callAround(toks: Tok[], k: number): Call | null {
  let depth = 0
  let open = -1
  for (let j = k - 1; j >= 0; j--) {
    const t = toks[j]
    if (t.t === 'nl') return null
    if (t.t === 'op' && ')]}'.includes(t.v)) depth++
    if (t.t === 'op' && '([{'.includes(t.v)) {
      if (depth === 0) {
        if (t.v !== '(') return null
        open = j
        break
      }
      depth--
    }
  }
  if (open < 1) return null
  const chain: string[] = []
  let j = open - 1
  while (j >= 0) {
    if (isOp(toks[j], ')')) {
      let d = 0
      for (; j >= 0; j--) {
        if (isOp(toks[j], ')')) d++
        if (isOp(toks[j], '(') && --d === 0) break
      }
      j--
      continue
    }
    if (!isName(toks[j])) break
    chain.unshift(toks[j].v)
    if (!isOp(toks[j - 1], '.')) break
    j -= 2
  }
  if (!chain.length) return null
  let close = open
  let d = 0
  const args: [number, number][] = []
  let argStart = open + 1
  for (let m = open; m < toks.length; m++) {
    const t = toks[m]
    if (t.t === 'op' && '([{'.includes(t.v)) d++
    if (t.t === 'op' && ')]}'.includes(t.v)) {
      d--
      if (d === 0) { close = m; break }
    }
    if (d === 1 && isOp(t, ',')) {
      args.push([argStart, m])
      argStart = m + 1
    }
  }
  if (argStart < close) args.push([argStart, close])
  return { open, close, chain, args }
}

/** An explicit method in the arguments: `method="POST"`, or a bare "POST". */
function verbInArgs(toks: Tok[], args: [number, number][]): string | null {
  for (const [a, b] of args) {
    const part = toks.slice(a, b)
    if (part.length === 3 && isName(part[0], 'method') && isOp(part[1], '=') && part[2].t === 'str') {
      if (VERBS.has(part[2].v)) return part[2].v
    }
    if (part.length === 1 && part[0].t === 'str' && VERBS.has(part[0].v)) return part[0].v
  }
  return null
}

const hasKwarg = (toks: Tok[], args: [number, number][], name: string) =>
  args.some(([a]) => isName(toks[a], name) && isOp(toks[a + 1], '='))

type DefIndex = Map<string, { file: PyFile; at: number }[]>

function indexDefs(files: PyFile[]): DefIndex {
  const out: DefIndex = new Map()
  for (const file of files) {
    file.toks.forEach((t, k) => {
      if (isName(t, 'def') && isName(file.toks[k + 1])) {
        const name = file.toks[k + 1].v
        if (!out.has(name)) out.set(name, [])
        out.get(name)!.push({ file, at: k })
      }
    })
  }
  return out
}

/** The name an alias stands for: `import x as alias` or `alias = x`. */
function unalias(file: PyFile, name: string): string {
  const toks = file.toks
  for (let k = 2; k < toks.length; k++) {
    if (isName(toks[k], name) && isName(toks[k - 1], 'as') && isName(toks[k - 2])) return toks[k - 2].v
    if (isName(toks[k], name) && isStmtStart(toks, k) && isOp(toks[k + 1], '=') && isName(toks[k + 2])
      && toks[k + 3]?.t === 'nl') return toks[k + 2].v
  }
  return name
}

/** The method a helper function requests its URL with, read from its definition. */
function helperVerb(defs: DefIndex, file: PyFile, name: string): string | null {
  const found = new Set<string>()
  for (const { file: df, at } of defs.get(unalias(file, name)) ?? []) {
    const toks = df.toks
    const open = at + 2
    let d = 0
    let close = open
    for (let m = open; m < toks.length; m++) {
      if (isOp(toks[m], '(')) d++
      if (isOp(toks[m], ')') && --d === 0) { close = m; break }
    }
    let fromDefault: string | null = null
    for (let m = open; m < close; m++) {
      if (!isName(toks[m], 'method')) continue
      let j = m + 1
      while (j < close && !isOp(toks[j], '=') && !isOp(toks[j], ',')) j++
      if (isOp(toks[j], '=') && toks[j + 1]?.t === 'str' && VERBS.has(toks[j + 1].v)) fromDefault = toks[j + 1].v
    }
    if (fromDefault) { found.add(fromDefault); continue }
    const defIndent = toks[at].indent
    let end = close + 1
    while (end < toks.length && !(isStmtStart(toks, end) && toks[end].indent <= defIndent)) end++
    for (let m = close; m < end; m++) {
      if (!isOp(toks[m], '(') || !isName(toks[m - 1])) continue
      const call = callAround(toks, m + 1)
      if (!call) continue
      const last = call.chain[call.chain.length - 1]
      if (last === 'Request') {
        found.add(verbInArgs(toks, call.args) ?? (hasKwarg(toks, call.args, 'data') ? 'POST' : 'GET'))
      } else if (call.chain.length === 2 && ['requests', 'httpx'].includes(call.chain[0]) && VERBS.has(last.toUpperCase())) {
        found.add(last.toUpperCase())
      }
    }
  }
  return found.size === 1 ? [...found][0] : null
}

/** The method of the call that holds the URL as its argument number `urlArg`. */
function callVerb(defs: DefIndex, file: PyFile, call: Call, urlArg: number): string | null {
  const toks = file.toks
  const last = call.chain[call.chain.length - 1]
  if (last === 'to_thread') {
    const [a, b] = call.args[0] ?? [0, 0]
    if (b - a !== 1 || !isName(toks[a])) return null
    const rest = call.args.filter((_, idx) => idx !== 0 && idx !== urlArg)
    return verbInArgs(toks, rest) ?? helperVerb(defs, file, toks[a].v)
  }
  if (call.chain.length > 1 && VERBS.has(last.toUpperCase())) return last.toUpperCase()
  const explicit = verbInArgs(toks, call.args)
  if (explicit) return explicit
  if (last === 'Request') return hasKwarg(toks, call.args, 'data') ? 'POST' : 'GET'
  return helperVerb(defs, file, last)
}

const argIndex = (call: Call, k: number) => call.args.findIndex(([a, b]) => k >= a && k < b)

/** Tokens s..e are a whole argument: positional, or the value of `kw=`. */
function isArgument(toks: Tok[], s: number, e: number): boolean {
  const before = toks[s - 1]
  const opensArg = (t: Tok | undefined) => isOp(t, '(') || isOp(t, ',')
  const starts = opensArg(before) || (isOp(before, '=') && isName(toks[s - 2]) && opensArg(toks[s - 3]))
  return starts && (isOp(toks[e + 1], ',') || isOp(toks[e + 1], ')'))
}

/** The end of the function (or module) that token k belongs to. */
function scopeEnd(toks: Tok[], k: number): number {
  const own = toks[k].indent
  for (let j = k - 1; j >= 0; j--) {
    if (isName(toks[j], 'def') && toks[j].indent < own
      && (isStmtStart(toks, j) || (isName(toks[j - 1], 'async') && isStmtStart(toks, j - 1)))) {
      const defIndent = toks[j].indent
      for (let m = k + 1; m < toks.length; m++) if (isStmtStart(toks, m) && toks[m].indent <= defIndent) return m
      return toks.length
    }
  }
  return toks.length
}

type Resolved = { verbs: string[] } | { problem: string } | { skip: true }

function resolveSite(defs: DefIndex, site: UrlSite, prefixNames: Set<string>): Resolved {
  const toks = site.file.toks
  const { s, e } = site.str
  if (isName(toks[s - 1], 'return')) return { problem: 'the URL is returned and completed by its callers' }

  const direct = callAround(toks, s)
  if (direct && isArgument(toks, s, e)) {
    const verb = callVerb(defs, site.file, direct, argIndex(direct, s))
    return verb ? { verbs: [verb] } : { problem: `cannot tell the method of ${direct.chain.join('.')}(...)` }
  }

  let eq = s - 1
  let after = e + 1
  if (isOp(toks[eq], '(') && isOp(toks[after], ')')) { eq--; after++ }
  if (!isOp(toks[eq], '=') || !isName(toks[eq - 1]) || !isStmtStart(toks, eq - 1)
    || (after < toks.length && toks[after].t !== 'nl')) {
    return { problem: 'the URL is neither a call argument nor assigned to a name' }
  }
  const name = toks[eq - 1].v
  const end = scopeEnd(toks, eq - 1)
  const verbs = new Set<string>()
  for (let k = after; k < end; k++) {
    if (isName(toks[k], name) && isStmtStart(toks, k) && isOp(toks[k + 1], '=') && !isOp(toks[k + 2], '=')) break
    if (!isName(toks[k], name) || !isArgument(toks, k, k)) continue
    const call = callAround(toks, k)
    if (!call || NOT_A_REQUEST.has(call.chain[0])) continue
    const verb = callVerb(defs, site.file, call, argIndex(call, k))
    if (!verb) return { problem: `cannot tell the method of ${call.chain.join('.')}(${name}, ...)` }
    verbs.add(verb)
  }
  if (verbs.size) return { verbs: [...verbs] }
  if (prefixNames.has(name)) return { skip: true }
  return { problem: `${name} is never passed to a request` }
}

/** One segment per placeholder, the query string dropped; null if that is not possible. */
function samplePath(path: string): string | null {
  let cut = path.length
  let depth = 0
  for (let k = 0; k < path.length; k++) {
    if (path[k] === '{') depth++
    if (path[k] === '}') depth--
    if (depth === 0 && (path[k] === '?' || path[k] === '#')) { cut = k; break }
  }
  const bare = path.slice(0, cut)
  if (/\}\{/.test(bare)) return null
  const sample = bare.replace(/\{[^{}]*\}/g, 'x')
  return /[{}]/.test(sample) ? null : sample
}

// ---------------------------------------------------------------------------

type Extracted = {
  calls: { method: string; path: string; display: string; at: string; scanner: boolean }[]
  problems: { at: string; literal: string; problem: string }[]
  others: { file: string; base: string; line: number }[]
}

function extract(files: PyFile[]): Extracted {
  const defs = indexDefs(files)
  const others: Extracted['others'] = []
  const calls: Extracted['calls'] = []
  const problems: Extracted['problems'] = []
  for (const file of files) {
    const sites = webappSites(file, others)
    const prefixNames = new Set(
      sites.flatMap(site => {
        const m = LEADING_PLACEHOLDER.exec(site.str.text)
        return m && !site.str.text.slice(m[0].length).startsWith('/api/') ? [m[1].trim()] : []
      }),
    )
    for (const site of sites) {
      const at = `${file.rel}:${site.str.line}`
      const r = resolveSite(defs, site, prefixNames)
      if ('skip' in r) continue
      const path = samplePath(site.path)
      if ('problem' in r || path === null) {
        problems.push({ at, literal: site.str.text, problem: 'problem' in r ? r.problem : 'the path cannot be read' })
        continue
      }
      const display = site.path.split(/[?#]/)[0].replace(/\{[^{}]*\}/g, '{}')
      for (const method of r.verbs) calls.push({ method, path, display, at, scanner: file.scannerFirst })
    }
  }
  return { calls, problems, others }
}

const allowed = (method: string, path: string) =>
  internalKeyRouteAllowed(method, path) || scannerKeyRouteAllowed(method, path)

const listedAs = (u: { at: string; literal: string }, p: { at: string; literal: string }) =>
  u.literal === p.literal && p.at.startsWith(`${u.at.split(':')[0]}:`)

// The extractor on the call shapes the services use, so a change to it that
// silently stops seeing one fails here rather than shrinking what is checked.
describe('the call-site extractor', () => {
  const routes = (...files: [string, string][]) => {
    const found = extract(files.map(([rel, src]) => parseFile(rel, src)))
    return {
      calls: found.calls.map(c => `${c.method} ${c.path}${c.scanner ? ' (scanner key)' : ''}`).sort(),
      problems: found.problems.map(p => p.problem),
      others: found.others.map(o => o.base),
    }
  }

  test('a direct call, implicit concatenation, a query string and a comment', () => {
    expect(routes(['a.py', [
      'H = {"X-Internal-Key": KEY}',
      '# client.post(f"{WEBAPP_API_URL}/api/commented/out")',
      'async def f(session_id):',
      '    await client.patch(f"{WEBAPP_API_URL}/api/conversations/by-session/{session_id}"',
      '                       f"/fireteams/{x(\'id\')}?a=1", headers=H)',
      '    requests.get(f"{webapp_url.rstrip(\'/\')}/api/users/{uid}/settings?internal=true", headers=H)',
    ].join('\n')]).calls).toEqual([
      'GET /api/users/x/settings',
      'PATCH /api/conversations/by-session/x/fireteams/x',
    ])
  })

  test('a URL assigned to a name, followed to the request in the same function only', () => {
    expect(routes(['a.py', [
      'def f():',
      '    url = (f"{webapp_url}/api/projects/{pid}"',
      '           f"/x")',
      '    logger.info("fetching", url)',
      '    r = requests.post(url, json={})',
      'def g(url):',
      '    requests.delete(url)',
    ].join('\n')]).calls).toEqual(['POST /api/projects/x/x'])
  })

  test('helpers: an explicit method, a default, an alias, to_thread, and urllib Request', () => {
    const helpers = [
      'def request_json(url, key, method: str = "GET", payload=None):',
      '    return None',
      'def _post_status(url, key, timeout):',
      '    req = urllib.request.Request(url, data=b"{}", headers={"x-internal-key": key})',
    ].join('\n')
    const caller = [
      'from webapp_client import request_json as _rq',
      '_request = request_json',
      'base, key = webapp_base(), internal_key()',
      'def tick():',
      '    _rq(f"{base}/api/internal/a", key)',
      '    _rq(f"{base}/api/internal/b", key, "POST", {})',
      '    asyncio.to_thread(_request, f"{base}/api/internal/c", key)',
      '    asyncio.to_thread(_request, f"{base}/api/internal/d", key, method="PUT")',
      '    url = f"{base}/api/internal/e"',
      '    asyncio.to_thread(_post_status, url, key, 5.0)',
      '    urllib.request.Request(f"{base}/api/internal/f")',
    ].join('\n')
    expect(routes(['webapp_client.py', helpers], ['caller.py', caller]).calls).toEqual([
      'GET /api/internal/a',
      'GET /api/internal/c',
      'GET /api/internal/f',
      'POST /api/internal/b',
      'POST /api/internal/e',
      'PUT /api/internal/d',
    ])
  })

  test('a module constant used directly and as a prefix', () => {
    expect(routes(['a.py', [
      'INTERNAL_HEADERS = {}',
      '_ENDPOINT = f"{WEBAPP_API_URL}/api/internal/one"',
      '_BASE = f"{WEBAPP_API_URL}/api/internal/two"',
      'async def f(job_id):',
      '    await client.post(_ENDPOINT, headers=INTERNAL_HEADERS)',
      '    await client.post(f"{_BASE}/{job_id}/start", headers=INTERNAL_HEADERS)',
    ].join('\n')]).calls).toEqual(['POST /api/internal/one', 'POST /api/internal/two/x/start'])
  })

  test('what it cannot read is reported, never dropped', () => {
    const found = routes(['a.py', [
      'INTERNAL_HEADERS = {}',
      'def _url(suffix=""):',
      '    return f"{WEBAPP_API_URL}/api/internal/runs/{rid}{suffix}"',
      'def g():',
      '    mystery(f"{WEBAPP_API_URL}/api/internal/three")',
      '    requests.get(f"{OTHER_URL}/api/tags")',
      '    target = f"{WEBAPP_API_URL}/api/internal/four"',
    ].join('\n')])
    expect(found.calls).toEqual([])
    expect(found.problems).toEqual([
      'the URL is returned and completed by its callers',
      'cannot tell the method of mystery(...)',
      'target is never passed to a request',
    ])
    expect(found.others).toEqual(['OTHER_URL'])
  })

  test('a file that sends the scanner key first marks its calls as scanner calls', () => {
    expect(routes(['a.py', [
      'def f():',
      '    h = {"X-Internal-Key": (os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY", ""))}',
      '    requests.get(f"{webapp_url}/api/projects/{pid}", headers=h)',
    ].join('\n')], ['b.py', [
      'TAG_KEYS = {"recon": os.environ.get("SCANNER_API_KEY", "")}',
      'H = {"x-internal-key": os.environ.get("INTERNAL_API_KEY", "")}',
      'requests.get(f"{webapp}/api/projects/{pid}", headers=H)',
    ].join('\n')]).calls).toEqual(['GET /api/projects/x', 'GET /api/projects/x (scanner key)'])
  })
})

describe.skipIf(!available)('webapp routes the Python services call with X-Internal-Key (drift-map #19)', () => {
  const found = available ? extract(loadRepoFiles()) : { calls: [], problems: [], others: [] }

  test('the extractor finds the callers', () => {
    const distinct = new Set(found.calls.map(c => `${c.method} ${c.display}`))
    expect(distinct.size).toBeGreaterThanOrEqual(25)
    expect([...distinct]).toEqual(expect.arrayContaining([
      'GET /api/projects/{}',
      'POST /api/traffic/{}/ingest',
      'POST /api/internal/triage-runs/{}/heartbeat',
      'GET /api/internal/scan-schedules/due',
      'POST /api/internal/plugins/reconcile',
    ]))
  })

  test('every call site is understood, or listed with the routes it calls', () => {
    const unexplained = found.problems
      .filter(p => !UNPARSED_CALL_SITES.some(u => listedAs(u, p)))
      .map(p => `${p.at} ${p.literal}: ${p.problem}`)
    expect(unexplained, 'add the site to UNPARSED_CALL_SITES with the routes it calls').toEqual([])
  })

  test('every route they call is on INTERNAL_ALLOWLIST or SCANNER_ALLOWLIST', () => {
    const missing = [
      ...found.calls.filter(c => !allowed(c.method, c.path)).map(c => `${c.method} ${c.display} (${c.at})`),
      ...UNPARSED_CALL_SITES.flatMap(u => u.calls.filter(([m, p]) => !allowed(m, p)).map(([m, p]) => `${m} ${p} (${u.at})`)),
    ]
    expect(missing, 'add these to the allowlist in middleware.ts, or stop calling them with the key').toEqual([])
  })

  // The scanner key is enforced with no log-only phase, so a scan-container call
  // that is only on INTERNAL_ALLOWLIST is refused as soon as SCANNER_API_KEY is set.
  test('every route called with the scanner key first is on SCANNER_ALLOWLIST', () => {
    const scannerCalls = found.calls.filter(c => c.scanner)
    expect(scannerCalls.length).toBeGreaterThan(0)
    const refused = scannerCalls
      .filter(c => !scannerKeyRouteAllowed(c.method, c.path))
      .map(c => `${c.method} ${c.display} (${c.at})`)
    expect(refused).toEqual([])
  })

  test('every listed unparsed site still exists and still cannot be read', () => {
    const stale = UNPARSED_CALL_SITES
      .filter(u => !found.problems.some(p => listedAs(u, p)))
      .map(u => u.at)
    expect(stale).toEqual([])
  })

  test('a {base}/api/ URL in a keyed file is the webapp, or listed as another service', () => {
    const unknown = found.others
      .filter(o => !NOT_THE_WEBAPP.some(n => n.file === o.file && n.base === o.base))
      .map(o => `${o.file}:${o.line} {${o.base}}`)
    const stale = NOT_THE_WEBAPP
      .filter(n => !found.others.some(o => o.file === n.file && o.base === n.base))
      .map(n => `${n.file} {${n.base}}`)
    expect({ unknown, stale }).toEqual({ unknown: [], stale: [] })
  })
})
