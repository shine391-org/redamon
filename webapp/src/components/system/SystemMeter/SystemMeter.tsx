'use client'

import { useSystemStats, toGB } from '@/hooks/useSystemStats'
import styles from './SystemMeter.module.css'

function Meter({ label, pct, value, detail, tone }: { label: string; pct: number; value?: string; detail: string; tone?: 'low' | 'mid' | 'high' }) {
  const clamped = Math.min(100, Math.max(0, pct))
  // `tone` forces a fixed color (CPU is a USAGE metric, shown red, not a free-space one).
  const level = tone ?? (clamped > 90 ? 'high' : clamped > 70 ? 'mid' : 'low')
  return (
    <div className={styles.meter} title={detail}>
      <span className={styles.label}>{label}</span>
      <span className={styles.track}>
        <span className={`${styles.fill} ${styles[level]}`} style={{ width: `${clamped}%` }} />
      </span>
      <span className={styles.pct}>{Math.round(clamped)}%</span>
      {value && <span className={styles.value}>{value}</span>}
    </div>
  )
}

/**
 * htop-style RAM + CPU meters for the bottom-right of the footer (Part 5).
 * The RAM number shown is FREE ram (available), consistent with the bar % so the
 * two agree. The governor's separate "room for a new scan" (remaining_for_new,
 * which subtracts memory reserved by running scans) is in the tooltip.
 */
export function SystemMeter() {
  const { data, error } = useSystemStats()
  if (!data?.mem) {
    // Say the stats are missing and why, instead of the meters just vanishing.
    return error ? (
      <div className={styles.wrap} title={error.message} aria-label={error.message} role="status">
        <span className={styles.label}>RAM/CPU unavailable</span>
      </div>
    ) : null
  }

  const m = data.mem
  const total = m.host_total || 1
  const used = total - m.available
  const ramPct = (100 * used) / total
  const cpuPct = data.cpu?.percent ?? 0

  const disk = data.disk
  const diskTotal = disk?.total ?? 0
  const diskFree = disk?.free ?? 0
  const diskPct = diskTotal > 0 ? (100 * (diskTotal - diskFree)) / diskTotal : 0

  const ramTooltip = [
    `${toGB(m.available)} GB free of ${toGB(total)} GB (${Math.round(ramPct)}% used)`,
    `${toGB(m.remaining_for_new)} GB available for a new scan` +
      (m.active_scans ? ` (${m.active_scans} scan${m.active_scans === 1 ? '' : 's'} reserving ${toGB(m.committed)} GB)` : ''),
  ].join('\n')

  // Meters only. Queue/scan state lives in the Scans tab on /graph, not
  // behind a click on the RAM/CPU readout.
  return (
    <div className={styles.wrap}>
      <Meter label="RAM" pct={ramPct} tone="high" value={`${toGB(used)}/${toGB(total, 0)} GB used`} detail={ramTooltip} />
      {diskTotal > 0 && (
        <Meter
          label="DISK"
          pct={diskPct}
          tone="high"
          value={`${toGB(diskTotal - diskFree)}/${toGB(diskTotal, 0)} GB used`}
          detail={`${toGB(diskFree)} GB free of ${toGB(diskTotal)} GB (${Math.round(diskPct)}% used)`}
        />
      )}
      <Meter label="CPU" pct={cpuPct} tone="high" detail={`${Math.round(cpuPct)}% of ${data.cpu?.cores ?? '?'} cores`} />
    </div>
  )
}
