'use client'

import { AlertCircle } from 'lucide-react'
import styles from './AIAssistantDrawer.module.css'

/**
 * Says that the skill toggles and badges could not be loaded, with the cause
 * (code and HTTP status), instead of leaving it in the console. The badges keep
 * the last data that loaded.
 */
export function SkillDataNotice({ error }: { error: Error | string | null | undefined }) {
  if (!error) return null
  const text = typeof error === 'string' ? error : error.message
  return (
    <div className={styles.skillDataNotice} role="status">
      <AlertCircle size={11} />
      <span>Skill toggles could not be loaded: {text}</span>
    </div>
  )
}
