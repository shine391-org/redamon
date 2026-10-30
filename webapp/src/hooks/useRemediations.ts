/**
 * useRemediations Hook
 *
 * TanStack Query hook for fetching and mutating remediations.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchJson, fetchOk } from '@/lib/apiError'
import type { Remediation, RemediationSeverity, RemediationStatus } from '@/lib/cypherfix-types'

// =============================================================================
// QUERY KEYS
// =============================================================================

const REMEDIATIONS_KEY = 'remediations'

// =============================================================================
// FETCH FUNCTIONS
// =============================================================================

async function fetchRemediations(
  projectId: string,
  filters?: {
    status?: RemediationStatus
    severity?: RemediationSeverity
    sort?: string
    order?: 'asc' | 'desc'
  }
): Promise<Remediation[]> {
  const params = new URLSearchParams({ projectId })
  if (filters?.status) params.set('status', filters.status)
  if (filters?.severity) params.set('severity', filters.severity)
  if (filters?.sort) params.set('sort', filters.sort)
  if (filters?.order) params.set('order', filters.order)

  return fetchJson<Remediation[]>(`/api/remediations?${params}`, undefined, 'Failed to fetch remediations')
}

async function updateRemediation(
  id: string,
  data: Partial<Remediation>
): Promise<Remediation> {
  return fetchJson<Remediation>(`/api/remediations/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  }, 'Failed to update remediation')
}

async function deleteRemediation(id: string): Promise<void> {
  await fetchOk(`/api/remediations/${id}`, { method: 'DELETE' }, 'Failed to delete remediation')
}

async function updateBlockStatuses(
  id: string,
  fileChanges: Remediation['fileChanges']
): Promise<Remediation> {
  return fetchJson<Remediation>(`/api/remediations/${id}/blocks`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileChanges }),
  }, 'Failed to update block statuses')
}

// =============================================================================
// HOOKS
// =============================================================================

export interface UseRemediationsOptions {
  projectId: string
  status?: RemediationStatus
  severity?: RemediationSeverity
  sort?: string
  order?: 'asc' | 'desc'
  enabled?: boolean
}

export function useRemediations({
  projectId,
  status,
  severity,
  sort = 'priority',
  order = 'asc',
  enabled = true,
}: UseRemediationsOptions) {
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: [REMEDIATIONS_KEY, projectId, { status, severity, sort, order }],
    queryFn: () => fetchRemediations(projectId, { status, severity, sort, order }),
    enabled: enabled && !!projectId,
    staleTime: 30_000,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Remediation> }) =>
      updateRemediation(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REMEDIATIONS_KEY, projectId] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteRemediation(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REMEDIATIONS_KEY, projectId] })
    },
  })

  const updateBlocksMutation = useMutation({
    mutationFn: ({ id, fileChanges }: { id: string; fileChanges: Remediation['fileChanges'] }) =>
      updateBlockStatuses(id, fileChanges),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [REMEDIATIONS_KEY, projectId] })
    },
  })

  const refetch = () => {
    queryClient.invalidateQueries({ queryKey: [REMEDIATIONS_KEY, projectId] })
  }

  return {
    remediations: query.data ?? [],
    isLoading: query.isLoading,
    error: query.error,
    refetch,
    updateRemediation: updateMutation.mutate,
    deleteRemediation: deleteMutation.mutate,
    /** Resolve on success and reject with the ApiError, for a caller that must say when it failed. */
    updateRemediationAsync: updateMutation.mutateAsync,
    deleteRemediationAsync: deleteMutation.mutateAsync,
    updateBlocks: updateBlocksMutation.mutate,
    isUpdating: updateMutation.isPending,
    isDeleting: deleteMutation.isPending,
  }
}
