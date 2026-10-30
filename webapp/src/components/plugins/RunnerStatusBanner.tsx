'use client'

import { errorMessage } from '@/lib/apiError'
import { usePluginsStatus, type PluginsStatus } from '@/hooks/usePluginsStatus'

const WHY: Record<string, string> = {
  runner_not_configured: 'The runner key is not configured (PLUGIN_RUNNER_KEY).',
}

const UNAVAILABLE: Record<string, string> = {
  timeout: 'The plugin runner did not answer in time',
  unreachable: 'The plugin runner is not reachable',
  bad_response: 'The plugin runner answered with something RedAmon cannot read',
}

/** Why the runner is not usable: the reason and the proxy's code, or the runner's own code and status. */
function unreachableText(runner: PluginsStatus['runner']): string {
  const known = WHY[runner.error ?? '']
  if (known) return known
  if (runner.error === 'runner_unavailable') {
    const base = UNAVAILABLE[runner.reason ?? ''] ?? 'The plugin runner is not reachable'
    return `${base}${runner.proxyCode ? ` (${runner.proxyCode})` : runner.reason ? ` (${runner.reason})` : ''}.`
  }
  return `The plugin runner answered ${runner.error}${runner.upstreamStatus ? ` (HTTP ${runner.upstreamStatus})` : ''}.`
}

/**
 * Says when plugin actions cannot run; approved skill versions are data and keep applying
 * (D-21). A status that could not be read is said too: no banner would read as a working runner.
 */
export function RunnerStatusBanner() {
  const { data, error } = usePluginsStatus()
  const runner = data?.runner
  if (!runner && error) {
    return (
      <div className="alert alertWarning" role="alert" data-testid="runner-banner">
        <div className="alertContent">
          <div className="alertTitle">{errorMessage(error, 'Runner status unknown')}</div>
          <div className="alertMessage">Whether plugin actions can run is not known; approved skill versions keep applying.</div>
        </div>
      </div>
    )
  }
  if (!runner) return null
  if (runner.reachable && runner.state !== 'out_of_date') return null
  const reason = runner.reachable
    ? 'The plugin runner is out of date for this RedAmon: rebuild it with ./redamon.sh up.'
    : unreachableText(runner)
  return (
    <div className="alert alertWarning" role="alert" data-testid="runner-banner">
      <div className="alertContent">
        <div className="alertTitle">Plugin actions are unavailable; approved skill versions keep applying.</div>
        <div className="alertMessage">{reason}</div>
      </div>
    </div>
  )
}
