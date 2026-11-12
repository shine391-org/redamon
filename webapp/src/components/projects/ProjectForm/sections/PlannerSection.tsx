'use client'

import { useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { RegistryFields } from '../RegistryFields'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface PlannerSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function PlannerSection({ data, updateField }: PlannerSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle}>
          <button type="button" aria-expanded={isOpen} aria-controls="planner-controls"
            onClick={() => setIsOpen(!isOpen)}>Planner</button>
          <NodeInfoTooltip section="Planner" />
          <WikiInfoButton target="Planner" />
        </h2>
        <div className={styles.sectionHeaderRight}>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent} id="planner-controls">
          <p className={styles.sectionDescription}>
            Planner mode for run-scoped plan generation and dispatch. off is the patched legacy
            behaviour (no planner optimization, no changed commands). shadow plans and writes the
            run-scoped manifest but does not change what is dispatched. enforce applies the enabled
            consumer optimizations.
          </p>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel} htmlFor="planner-mode">Planner mode</label>
            <select
              id="planner-mode"
              className="select"
              value={data.plannerMode ?? 'off'}
              onChange={(e) => updateField('plannerMode', e.target.value)}
            >
              <option value="off">off</option>
              <option value="shadow">shadow</option>
              <option value="enforce">enforce</option>
            </select>
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Enable plan manifest</label>
              <Toggle
                aria-label="Enable plan manifest"
                checked={data.plannerManifestEnabled ?? false}
                onChange={(checked) => updateField('plannerManifestEnabled', checked)}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Enable AI tag consumer</label>
              <Toggle
                aria-label="Enable AI tag consumer"
                checked={data.plannerConsumerAiTags ?? false}
                onChange={(checked) => updateField('plannerConsumerAiTags', checked)}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Enable target-selection consumer</label>
              <Toggle
                aria-label="Enable target-selection consumer"
                checked={data.plannerConsumerTargetSelection ?? false}
                onChange={(checked) => updateField('plannerConsumerTargetSelection', checked)}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Enable two-pass consumer</label>
              <Toggle
                aria-label="Enable two-pass consumer"
                checked={data.plannerConsumerTwoPass ?? false}
                onChange={(checked) => updateField('plannerConsumerTwoPass', checked)}
              />
            </div>
          </div>
          <RegistryFields
            keys={['nucleiRoutingMode', 'jsReconFetchAdmission', 'arjunLateSources',
              'chunkCheckpointEnabled', 'checkpointBudgetPerGroup', 'checkpointBudgetPerTool']}
            data={data} updateField={updateField}
            title="Routing, admission and Group 6 Phase A checkpoints"
            description="Routing is independent of planner mode. Admission and late-source settings apply only when their tools run. Checkpoints and budgets cover tool/group chunks in Group 6 Phase A, not individual HTTP requests or the entire pipeline. 0 is unbounded. Saving settings never starts or continues a scan; continuation is a separate, confirmed action in graph diagnostics."
          />
        </div>
      )}
    </div>
  )
}
