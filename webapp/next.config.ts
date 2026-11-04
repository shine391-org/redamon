import type { NextConfig } from 'next'
import { existsSync, readFileSync } from 'fs'
import path from 'path'

/**
 * The packages `scripts/roe-extract.mjs` imports, with everything they require,
 * as tracing globs.
 *
 * The extractor is a child process, so no route imports these and the
 * standalone output would not ship them. Next copies an include glob as it is
 * and follows nothing, hence the closure; the image build runs the extractor's
 * self-test, so a package this misses fails the build rather than an upload.
 */
function packageClosure(roots: string[]): string[] {
  const modules = path.join(process.cwd(), 'node_modules')
  const seen = new Set<string>()
  const visit = (name: string) => {
    if (seen.has(name)) return
    const manifest = path.join(modules, name, 'package.json')
    if (!existsSync(manifest)) return // an optional dependency this platform skipped
    seen.add(name)
    const pkg = JSON.parse(readFileSync(manifest, 'utf8'))
    for (const dep of Object.keys({ ...pkg.dependencies, ...pkg.optionalDependencies })) visit(dep)
  }
  roots.forEach(visit)
  return [...seen].sort().map(name => `./node_modules/${name}/**`)
}

const ROE_EXTRACTOR_FILES = ['./scripts/roe-extract.mjs', ...packageClosure(['pdfjs-dist', 'mammoth'])]

const nextConfig: NextConfig = {
  output: 'standalone',

  serverExternalPackages: ['neo4j-driver', 'pdfjs-dist'],

  experimental: {
    // The middleware matches /api, so Next buffers each request body there and
    // silently cuts it at this size (default 10 MB): the route then fails to parse
    // a truncated upload. Equal to nginx's client_max_body_size 60m
    // (tooling/deploy/single-host/nginx), above the largest route cap (50 MB wordlists).
    proxyClientMaxBodySize: '60mb',
  },

  // Keys are picomatch globs matched with `contains`, so '/api/projects' also
  // covers '/api/projects/[id]/roe' (a literal '[id]' would be a character class).
  outputFileTracingIncludes: {
    '/api/roe/parse': ROE_EXTRACTOR_FILES,
    '/api/projects': ROE_EXTRACTOR_FILES,
  },

  images: {
    remotePatterns: [],
  },

  env: {
    NEO4J_URI: process.env.NEO4J_URI,
    NEO4J_USER: process.env.NEO4J_USER,
    NEO4J_PASSWORD: process.env.NEO4J_PASSWORD,
    NEXT_PUBLIC_REDAMON_VERSION: process.env.NEXT_PUBLIC_REDAMON_VERSION,
  },
}

export default nextConfig
