/**
 * Every copy button must go through `copyText`, never `navigator.clipboard`.
 *
 * RedAmon is usually opened from another machine at http://<lan-ip>:3000. That
 * is not a secure context, so `navigator.clipboard` is undefined there and a
 * raw `navigator.clipboard.writeText(...)` throws on click: the button looks
 * dead for every remote user while working fine on the host's localhost.
 * `copyText` falls back to `execCommand('copy')`, which still works over http.
 *
 * Run: npx vitest run src/lib/copyText.consumers.test.ts
 */
import { describe, test, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'fs'
import { join, relative } from 'path'

const SRC = join(__dirname, '..')
const HELPER = join(__dirname, 'copyText.ts')
// navigator.clipboard, navigator?.clipboard, navigator['clipboard']
const RAW_CLIPBOARD = /navigator\s*\??\.\s*clipboard|navigator\s*\[\s*['"`]clipboard/

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sourceFiles(path)
    if (!/\.(ts|tsx)$/.test(name) || /\.test\.(ts|tsx)$/.test(name)) return []
    return [path]
  })
}

describe('clipboard access', () => {
  test('only lib/copyText.ts touches navigator.clipboard', () => {
    const files = sourceFiles(SRC)
    // A walk that found nothing would pass vacuously.
    expect(files).toContain(HELPER)
    const offenders = files
      .filter(f => f !== HELPER && RAW_CLIPBOARD.test(readFileSync(f, 'utf8')))
      .map(f => relative(SRC, f))
    expect(offenders, "use copyText from '@/lib/copyText' instead").toEqual([])
  })
})
