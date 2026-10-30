import { useState, useEffect, useCallback, useRef } from 'react'
import { formatApiError, toApiError } from '@/lib/apiError'
import { MODELS_LOAD_FAILED, fetchModelOptions } from '@/components/shared/modelOptions'
import type { ModelOption } from '../modelUtils'

export function useModelPicker(userId: string, onModelChange?: (modelId: string) => void) {
  const [showModelModal, setShowModelModal] = useState(false)
  const [modelSearch, setModelSearch] = useState('')
  const [allModels, setAllModels] = useState<Record<string, ModelOption[]>>({})
  const [modelsLoading, setModelsLoading] = useState(false)
  // Null, or the failure with its cause, e.g. "Failed to load models (agent_unreachable · HTTP 503)".
  const [modelsError, setModelsError] = useState<string | null>(null)
  const modelSearchRef = useRef<HTMLInputElement>(null)

  // Fetch models when modal opens
  useEffect(() => {
    if (!showModelModal) return
    let cancelled = false
    setModelsLoading(true)
    setModelsError(null)
    fetchModelOptions(userId)
      .then(data => { if (!cancelled) setAllModels(data) })
      .catch(err => {
        if (!cancelled) setModelsError(formatApiError({ ...toApiError(err, MODELS_LOAD_FAILED), reason: MODELS_LOAD_FAILED }))
      })
      .finally(() => { if (!cancelled) setModelsLoading(false) })
    return () => { cancelled = true }
  }, [showModelModal, userId])

  // Auto-focus search when modal opens
  useEffect(() => {
    if (showModelModal) {
      setTimeout(() => modelSearchRef.current?.focus(), 0)
    } else {
      setModelSearch('')
    }
  }, [showModelModal])

  // Filter models by search
  const filteredModels: Record<string, ModelOption[]> = {}
  if (showModelModal) {
    const lowerSearch = modelSearch.toLowerCase()
    for (const [provider, models] of Object.entries(allModels)) {
      const filtered = models.filter(m =>
        m.id.toLowerCase().includes(lowerSearch) ||
        m.name.toLowerCase().includes(lowerSearch) ||
        m.description.toLowerCase().includes(lowerSearch)
      )
      if (filtered.length > 0) filteredModels[provider] = filtered
    }
  }

  const handleSelectModel = useCallback((id: string) => {
    onModelChange?.(id)
    setShowModelModal(false)
  }, [onModelChange])

  return {
    showModelModal,
    setShowModelModal,
    modelSearch,
    setModelSearch,
    modelsLoading,
    modelsError,
    filteredModels,
    handleSelectModel,
    modelSearchRef,
  }
}
