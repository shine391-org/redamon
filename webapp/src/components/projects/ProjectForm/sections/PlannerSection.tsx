'use client'

import { useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
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
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          Planner
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
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Planner mode for run-scoped plan generation and dispatch. off is the patched legacy
            behaviour (no planner optimization, no changed commands). shadow plans and writes the
            run-scoped manifest but does not change what is dispatched. enforce applies the enabled
            consumer optimizations.
          </p>

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Planner mode</label>
            <select
              className="select"
              value={data.plannerMode}
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
                checked={data.plannerManifestEnabled}
                onChange={(checked) => updateField('plannerManifestEnabled', checked)}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Enable AI tag consumer</label>
              <Toggle
                checked={data.plannerConsumerAiTags}
                onChange={(checked) => updateField('plannerConsumerAiTags', checked)}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Enable target-selection consumer</label>
              <Toggle
                checked={data.plannerConsumerTargetSelection}
                onChange={(checked) => updateField('plannerConsumerTargetSelection', checked)}
              />
            </div>
            <div className={styles.fieldGroup}>
              <label className={styles.fieldLabel}>Enable two-pass consumer</label>
              <Toggle
                checked={data.plannerConsumerTwoPass}
                onChange={(checked) => updateField('plannerConsumerTwoPass', checked)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
