'use client'

import { useEffect } from 'react'
import Link from 'next/link'
import { AlertTriangle, ArrowLeft } from 'lucide-react'
import styles from './page.module.css'

const isChunkLoadError = (error: Error) =>
  error.name === 'ChunkLoadError' ||
  /Loading chunk [\w/.-]+ failed/i.test(error.message) ||
  /Failed to load chunk/i.test(error.message)

/**
 * A plugin page whose server render failed (the plugin row could not be read, say). In a
 * production build Next replaces the message with a generic one, so the digest is what ties
 * the screen to the webapp's log line.
 */
export default function PluginNavError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    if (isChunkLoadError(error)) {
      window.location.reload()
      return
    }
    console.error('Plugin page error:', error)
  }, [error])

  if (isChunkLoadError(error)) return null

  return (
    <main className={styles.page}>
      <header className={styles.header}>
        <Link href="/plugins" className={styles.back}>
          <ArrowLeft size={14} aria-hidden /> Plugins
        </Link>
      </header>
      <div className={styles.error} role="alert">
        <AlertTriangle size={16} aria-hidden /> This plugin page could not be loaded
        {error.digest ? ` (error reference ${error.digest}; the webapp log has the details)` : ''}.
        <button type="button" className="secondaryButton" onClick={reset}>
          Try again
        </button>
      </div>
    </main>
  )
}
