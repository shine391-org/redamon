'use client'

import { useState, useCallback, useMemo } from 'react'
import { useRemediations } from '@/hooks'
import { useAlertModal } from '@/components/ui'
import { errorMessage } from '@/lib/apiError'
import { useProjectById } from '@/hooks/useProjects'
import type { UseCypherFixTriageWSReturn } from '@/hooks/useCypherFixTriageWS'
import { EmptyState } from './EmptyState/EmptyState'
import { RemediationDashboard } from './RemediationDashboard/RemediationDashboard'
import { RemediationDetail } from './RemediationDetail/RemediationDetail'
import { DiffViewer } from './DiffViewer/DiffViewer'
import { TriageProgress } from './TriageProgress/TriageProgress'
import { TriageRunBanner } from '@/components/triage/TriageRunBanner'
import type { Remediation, RemediationSeverity, RemediationStatus } from '@/lib/cypherfix-types'
import styles from './CypherFixTab.module.css'

type SubView = 'dashboard' | 'detail' | 'diffviewer'

interface CypherFixTabProps {
  projectId: string
  userId: string
  triage: UseCypherFixTriageWSReturn
  showTriageProgress: boolean
  onStartTriage: () => void
  /** Open the progress panel over a run that is only shown as the banner. */
  onOpenTriageProgress?: () => void
  onCloseTriageProgress: () => void
}

export function CypherFixTab({
  projectId,
  userId,
  triage,
  showTriageProgress,
  onStartTriage,
  onOpenTriageProgress,
  onCloseTriageProgress,
}: CypherFixTabProps) {
  const [subView, setSubView] = useState<SubView>('dashboard')
  const [selectedRemediation, setSelectedRemediation] = useState<Remediation | null>(null)
  const [severityFilter, setSeverityFilter] = useState<RemediationSeverity | undefined>()
  const [statusFilter, setStatusFilter] = useState<RemediationStatus | undefined>()

  const {
    remediations,
    isLoading,
    error,
    refetch,
    updateRemediationAsync,
    deleteRemediationAsync,
  } = useRemediations({
    projectId,
    severity: severityFilter,
    status: statusFilter,
  })

  const { data: project } = useProjectById(projectId || null)

  const missingSettings = useMemo(() => {
    if (!project) return []
    const missing: string[] = []
    if (!project.cypherfixGithubToken) missing.push('GitHub Token (CypherFix)')
    if (!project.cypherfixDefaultRepo) missing.push('Default Repository')
    if (!project.cypherfixDefaultBranch) missing.push('Default Branch')
    if (!project.cypherfixBranchPrefix) missing.push('Branch Prefix')
    return missing
  }, [project])

  const handleSelectRemediation = useCallback((remediation: Remediation) => {
    setSelectedRemediation(remediation)
    setSubView('detail')
  }, [])

  const handleBackToDashboard = useCallback(() => {
    setSubView('dashboard')
    setSelectedRemediation(null)
  }, [])

  const handleStartCodeFix = useCallback((remediationId: string) => {
    const rem = remediations.find(r => r.id === remediationId) || selectedRemediation
    if (rem) {
      setSelectedRemediation(rem)
      setSubView('diffviewer')
    }
  }, [remediations, selectedRemediation])

  const handleBackToDetail = useCallback(() => {
    setSubView('detail')
  }, [])

  const { alertError } = useAlertModal()

  const handleDismiss = useCallback(async (id: string) => {
    try {
      await updateRemediationAsync({ id, data: { status: 'dismissed' } })
    } catch (e) {
      await alertError(errorMessage(e, 'The remediation could not be dismissed'), 'Dismiss')
    }
  }, [updateRemediationAsync, alertError])

  const handleDelete = useCallback(async (id: string) => {
    try {
      await deleteRemediationAsync(id)
    } catch (e) {
      // Stay on the remediation: going back looked like the delete worked.
      await alertError(errorMessage(e, 'The remediation could not be deleted'), 'Delete')
      return
    }
    if (selectedRemediation?.id === id) {
      handleBackToDashboard()
    }
  }, [deleteRemediationAsync, selectedRemediation, handleBackToDashboard, alertError])

  // A failed load is not an empty project: the dashboard shows the error
  // rather than offering to start triage over remediations that exist.
  const showEmpty = !isLoading && !error && remediations.length === 0 && !severityFilter && !statusFilter

  const running = triage.status === 'running'
  // A live run this page is not showing in the panel: one re-attached after a
  // reload, or started on the Priority Board or over MCP.
  const banner = running && !showTriageProgress ? (
    <TriageRunBanner
      projectId={projectId || null}
      label="Triage running"
      phase={triage.currentPhase}
      hint="The fix list updates when it publishes; you can leave this page"
      notice={triage.notice}
      onDetails={onOpenTriageProgress}
      onStop={triage.stopTriage}
    />
  ) : null

  const renderContent = () => {
    if (showEmpty) {
      return (
        <EmptyState
          onStartTriage={onStartTriage}
          projectId={projectId || null}
          running={running}
          banner={banner}
        />
      )
    }
    if (subView === 'diffviewer' && selectedRemediation) {
      return (
        <DiffViewer
          remediation={selectedRemediation}
          projectId={projectId}
          userId={userId}
          onBack={handleBackToDetail}
          onRefresh={refetch}
        />
      )
    }
    if (subView === 'detail' && selectedRemediation) {
      return (
        <RemediationDetail
          remediation={selectedRemediation}
          projectId={projectId}
          userId={userId}
          onBack={handleBackToDashboard}
          onDismiss={handleDismiss}
          onDelete={handleDelete}
          onRefresh={refetch}
          onStartCodeFix={handleStartCodeFix}
          missingSettings={missingSettings}
        />
      )
    }
    return (
      <RemediationDashboard
        remediations={remediations}
        isLoading={isLoading}
        error={error}
        severityFilter={severityFilter}
        statusFilter={statusFilter}
        onSeverityFilterChange={setSeverityFilter}
        onStatusFilterChange={setStatusFilter}
        onSelectRemediation={handleSelectRemediation}
        onDismiss={handleDismiss}
        onDelete={handleDelete}
        onRefresh={refetch}
        onStartTriage={onStartTriage}
        running={running}
        banner={banner}
        projectId={projectId}
        userId={userId}
      />
    )
  }

  return (
    <div className={styles.container}>
      {renderContent()}
      <TriageProgress
        isVisible={showTriageProgress}
        phase={triage.currentPhase}
        progress={triage.progress}
        findings={triage.findings}
        thinking={triage.thinking}
        error={triage.error}
        notice={triage.notice}
        status={triage.status}
        onClose={onCloseTriageProgress}
        onStop={triage.stopTriage}
      />
    </div>
  )
}
