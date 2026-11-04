import { fetchOk } from '@/lib/apiError'

/**
 * Downloads a plugin's data export (GET /api/plugins/<id>/export) through JS. A plain link
 * would save a refusal's JSON body as if it were the export, and the purge flow would count
 * it as downloaded; here a failure throws an ApiError ("… (code · HTTP n)") to show instead.
 * Resolves only once the file was handed to the browser, which is what unlocks a purge.
 */
export async function downloadPluginExport(pluginId: string): Promise<void> {
  const res = await fetchOk(`/api/plugins/${encodeURIComponent(pluginId)}/export`, { cache: 'no-store' }, 'The export could not be downloaded')
  const blob = await res.blob()
  const named = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') ?? '')?.[1]
  const url = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = url
    a.download = named ?? `${pluginId}-export.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    // After the click has handed the blob to the download; revoking at once can cancel it.
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }
}
