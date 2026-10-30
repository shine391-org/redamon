/**
 * What to tell a person about an agent socket (chat, Kali terminal) that closed.
 *
 * The agent writes its own close reasons ("Orchestrator not initialized",
 * "Server busy (low memory) - retry shortly", "Invalid or missing ticket"),
 * fixed text that is safe to show. A socket the agent refused before the
 * handshake, or that never reached it, closes with a bare 1006.
 */

const REASON_MAX = 123

/** "close 1013: Server busy (low memory) - retry shortly". */
export function describeWsClose(code: number, reason: string | undefined | null): string {
  const clean = (reason ?? '').replace(/\s+/g, ' ').trim().slice(0, REASON_MAX)
  if (clean) return `close ${code}: ${clean}`
  if (code === 1006) return 'close 1006: no answer from the agent (down, restarting, or the handshake was refused)'
  return `close ${code}`
}

/** The socket URL as it may be shown: scheme, host and path, never the query (it can hold a ticket). */
export function wsUrlForDisplay(url: string): string {
  return url.split(/[?#]/)[0]
}
