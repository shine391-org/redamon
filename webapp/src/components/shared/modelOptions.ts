/**
 * The user's selectable models, the one /api/models read every picker shares.
 * Its own module because ModelPicker and FeatureModelGate both need it, and the
 * gate already imports the picker.
 */
import { ApiError, fetchJson } from '@/lib/apiError'
import type { ModelOption } from '@/app/graph/components/AIAssistantDrawer/modelUtils'

export type ModelsByProvider = Record<string, ModelOption[]>

export const MODELS_LOAD_FAILED = 'Failed to load models'

/**
 * The models grouped by provider. Without a userId the agent lists only the models of
 * the providers set in its environment. Throws an ApiError: its code tells the agent
 * not running (agent_unreachable) from the agent failing (agent_error).
 */
export async function fetchModelOptions(userId?: string | null): Promise<ModelsByProvider> {
  const data = await fetchJson<unknown>('/api/models', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userId ? { userId } : {}),
    cache: 'no-store',
  }, MODELS_LOAD_FAILED)
  if (!data || typeof data !== 'object' || Array.isArray(data) || (data as { error?: unknown }).error) {
    throw new ApiError({ reason: MODELS_LOAD_FAILED, status: 200, code: 'invalid_response' })
  }
  return data as ModelsByProvider
}
