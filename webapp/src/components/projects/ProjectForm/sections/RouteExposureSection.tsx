'use client'

import { useState } from 'react'
import { ChevronDown, DoorOpen, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { RegistryFields } from '../RegistryFields'
import { AiToggleLabel } from '../AiToggleLabel'
import { JevEngineControl } from '../JevEngineControl'
import { useHasJevProvider } from '@/hooks/useHasJevProvider'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface RouteExposureSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
  /** Opens Target & Modules, where the authentication profile is set. */
  onOpenAuth?: () => void
  /** Opens AI Agent > Agent Skills, where Broken Access Control is turned on. */
  onOpenAgentSkills?: () => void
}

/** A tab name inside a hint: a link when the form can switch tabs, plain text otherwise. */
function TabLink({ onOpen, children }: { onOpen?: () => void; children: React.ReactNode }) {
  if (!onOpen) return <>{children}</>
  return (
    <button
      type="button"
      onClick={onOpen}
      style={{ background: 'none', border: 0, padding: 0, color: 'var(--accent-primary)',
               fontWeight: 500, cursor: 'pointer' }}
    >
      {children}
    </button>
  )
}

/**
 * Route exposure: an active GROUP 6 Phase A scanner. It requests the routes
 * recon found plus the ones it generates, anonymously and logged in, and writes
 * leads for the agent and findings a signature proves.
 */
export function RouteExposureSection({ data, updateField, onRun, onOpenAuth, onOpenAgentSkills }: RouteExposureSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const enabled = !!data.routeExposureEnabled
  const jevStatus = useHasJevProvider()
  // Read as the agent reads it (get_enabled_builtin_skills): only a truthy value
  // is on, so a project saved before a skill existed shows the alert.
  const builtIn = (data.attackSkillConfig as { builtIn?: Record<string, unknown> } | null)?.builtIn ?? {}
  const skillOn = (id: string) => !!builtIn[id]

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <DoorOpen size={16} />
          Route Exposure
          <NodeInfoTooltip section="RouteExposure" />
          <WikiInfoButton target="RouteExposure" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run Route Exposure scan"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={enabled}
              onChange={(checked) => updateField('routeExposureEnabled', checked ?? false)}
              aria-label="Enable Route Exposure"
            />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Requests the routes recon found, and routes it generates, without credentials, and logged in
            where your authentication profile covers the host. Writes Vulnerability nodes: leads for the
            agent to confirm, and findings a signature proves (exposed .git and .env files, backups, debug
            consoles). Sends GET and HEAD only and never requests logout, delete or reset paths.
          </p>

          {enabled && !skillOn('access_control') && (
            <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`} role="alert">
              <strong>Half a cycle.</strong> Recon writes leads, but nothing confirms them: turn on Broken Access
              Control in <TabLink onOpen={onOpenAgentSkills}>AI Agent &gt; Agent Skills</TabLink>.
            </p>
          )}
          {enabled && (!skillOn('path_traversal') || !skillOn('rce')) && (
            <p className={styles.fieldHint}>
              Exposed files and consoles are proven by Path Traversal and RCE.
            </p>
          )}

          {enabled && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>What it requests</label>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Seed paths</div>
                    <div className={styles.toggleDescription}>
                      Well-known internal, admin and debug paths at each host and under each API prefix recon
                      saw, at most 60 per host. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureSeedPaths ?? true}
                    onChange={(c) => updateField('routeExposureSeedPaths', c ?? true)}
                    aria-label="Seed paths"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Version control and env files</div>
                    <div className={styles.toggleDescription}>
                      .git, .svn, .hg, .env and web.config at each host and under each top-level folder, at most
                      30 per host. These always get a request. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureVcsFiles ?? true}
                    onChange={(c) => updateField('routeExposureVcsFiles', c ?? true)}
                    aria-label="Version control and env files"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Backup file variants</div>
                    <div className={styles.toggleDescription}>
                      Backup copies of the server-side files recon found, plus root archives and dumps. Each
                      is read with HEAD and its first kilobyte, never downloaded. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureBackupFiles ?? true}
                    onChange={(c) => updateField('routeExposureBackupFiles', c ?? true)}
                    aria-label="Backup file variants"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Older API versions</div>
                    <div className={styles.toggleDescription}>
                      Tries /api/v1/x next to a /api/v2/x route recon found, at most 3 per route. An old version
                      that answers while the new one is locked is a strong lead. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureVersionVariants ?? true}
                    onChange={(c) => updateField('routeExposureVersionVariants', c ?? true)}
                    aria-label="Older API versions"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Sibling routes</div>
                    <div className={styles.toggleDescription}>
                      From each API route, tries its collection, /export, /all and /list, and internal or admin
                      variants, at most 6 per route. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureSiblings ?? true}
                    onChange={(c) => updateField('routeExposureSiblings', c ?? true)}
                    aria-label="Sibling routes"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Framework paths</div>
                    <div className={styles.toggleDescription}>
                      Requests debug and management paths for the frameworks recon detected on the host (Spring
                      actuator, Django, Laravel, Rails, Go, .NET, PHP, Apache), at most 30 per host. The Spring
                      heap dump is checked with HEAD only. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureFrameworkSeeds ?? true}
                    onChange={(c) => updateField('routeExposureFrameworkSeeds', c ?? true)}
                    aria-label="Framework paths"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Follow route catalogs</div>
                    <div className={styles.toggleDescription}>
                      When an open list of routes is found (actuator mappings, an anonymous OpenAPI spec, Rails
                      routes), requests the routes it names once, at most 500 per host. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureFollowCatalogs ?? true}
                    onChange={(c) => updateField('routeExposureFollowCatalogs', c ?? true)}
                    aria-label="Follow route catalogs"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Git walk proof</div>
                    <div className={styles.toggleDescription}>
                      After an exposed .git, fetches the branch ref and one commit object to prove the repository
                      can be rebuilt. Stores only the proof, never the source. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureGitWalk ?? true}
                    onChange={(c) => updateField('routeExposureGitWalk', c ?? true)}
                    aria-label="Git walk proof"
                  />
                </div>

                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Cross-host</div>
                    <div className={styles.toggleDescription}>
                      Tries a path that hit on one host against the other in-scope hosts with the same technology
                      or page title, at most 50. Off by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureCrossHost ?? false}
                    onChange={(c) => updateField('routeExposureCrossHost', c ?? false)}
                    aria-label="Cross-host"
                  />
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>What it compares</label>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Compare with the logged-in answer</div>
                    <div className={styles.toggleDescription}>
                      Requests each route again with your authentication profile, where it covers the host, to
                      tell a personal page from a public one and to find routes that return too much to their
                      own user. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureCompareLoggedIn ?? true}
                    onChange={(c) => updateField('routeExposureCompareLoggedIn', c ?? true)}
                    aria-label="Compare with the logged-in answer"
                  />
                </div>
                <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
                  Needs an authentication profile: set it in{' '}
                  <TabLink onOpen={onOpenAuth}>Target &amp; Modules &gt; Authenticated Session</TabLink>
                  . Without one it still finds routes open to anyone.
                </p>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>What it reads</label>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Personal data detection</div>
                    <div className={styles.toggleDescription}>
                      Stores the kinds and counts of personal data in each answer, never the values. On by
                      default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposurePiiDetection ?? true}
                    onChange={(c) => updateField('routeExposurePiiDetection', c ?? true)}
                    aria-label="Personal data detection"
                  />
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>What it checks on sensitive routes</label>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Cross-origin (CORS)</div>
                    <div className={styles.toggleDescription}>
                      On a personal, sensitive logged-in route, resends the request with crafted Origin headers to
                      spot a reflected origin returned with credentials. Reads the response headers only, never a
                      body. On by default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureCorsRider ?? true}
                    onChange={(c) => updateField('routeExposureCorsRider', c ?? true)}
                    aria-label="Cross-origin (CORS)"
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <div className={styles.toggleLabel}>Cacheable logged-in content</div>
                    <div className={styles.toggleDescription}>
                      On a personal, sensitive logged-in route, checks whether the answer is marked cacheable, so a
                      cache could serve it to an anonymous visitor. Never plants or fetches from cache. On by
                      default.
                    </div>
                  </div>
                  <Toggle
                    checked={data.routeExposureCacheRider ?? true}
                    onChange={(c) => updateField('routeExposureCacheRider', c ?? true)}
                    aria-label="Cacheable logged-in content"
                  />
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Jev decisions</label>
                <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)' }}>
                  <AiToggleLabel
                    label="Rank routes with Jev"
                    tooltip={
                      'Jev is asked, per route, whether it is meant only for logged-in, internal or administrative callers, and its answer decides which routes fill the request budget after the always-requested ones: the routes it reads as private are requested first. The answer is saved on each lead. No always-requested route is ever cut; without a Jev answer the order is the built-in one. Same switch as in the Target tab AI panel. ' +
                      (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                    }
                  />
                  <JevEngineControl
                    variant="jevOnly"
                    value={data.routeExposureJevRank}
                    enabled={data.aiInPipeline}
                    jevStatus={jevStatus}
                    disabledHint='Enable "AI in Pipeline" in the Target tab to turn this on.'
                    onSelect={(on) => updateField('routeExposureJevRank', on)}
                  />
                </div>
                <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)' }}>
                  <AiToggleLabel
                    label="Spot disguised login walls with Jev"
                    tooltip={
                      'For the HTML pages kept as leads, Jev is asked whether each is really a login form, an error page or a placeholder. The body reaches Jev masked. Its page class is saved on the lead, and a lead it places as a login wall or error page at confidence 70 or more moves to the end of the list the agent confirms. No lead is ever dropped. Same switch as in the Target tab AI panel. ' +
                      (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                    }
                  />
                  <JevEngineControl
                    variant="jevOnly"
                    value={data.routeExposureJevWallCheck}
                    enabled={data.aiInPipeline}
                    jevStatus={jevStatus}
                    disabledHint='Enable "AI in Pipeline" in the Target tab to turn this on.'
                    onSelect={(on) => updateField('routeExposureJevWallCheck', on)}
                  />
                </div>
                <div className={styles.toggleRow} style={{ alignItems: 'center', gap: 'var(--space-2)' }}>
                  <AiToggleLabel
                    label="Assess leads with Jev"
                    tooltip={
                      'Jev is asked, per lead, which kind of route it is and how sensitive its answer is, from the evidence alone, never the route class or a value. Both answers are saved on the lead, and the agent confirms the most sensitive leads first; a lead Jev reads as public content at confidence 70 or more goes last. No lead is ever dropped and the route class is never rewritten. Same switch as in the Target tab AI panel. ' +
                      (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                    }
                  />
                  <JevEngineControl
                    variant="jevOnly"
                    value={data.routeExposureJevAssess}
                    enabled={data.aiInPipeline}
                    jevStatus={jevStatus}
                    disabledHint='Enable "AI in Pipeline" in the Target tab to turn this on.'
                    onSelect={(on) => updateField('routeExposureJevAssess', on)}
                  />
                </div>
              </div>
            </>
          )}

          {enabled && (
            <RegistryFields
              keys={['routeExposureMaxRps', 'routeExposureWorkers', 'routeExposureTimeout', 'routeExposureMaxRoutesPerHost', 'routeExposureMaxRoutesTotal']}
              data={data}
              updateField={updateField}
              title="Advanced"
              description="Requests per second, workers, timeout and route budgets. Bounds, defaults and descriptions come from the settings registry, so they are the same ones the API enforces."
            />
          )}
        </div>
      )}
    </div>
  )
}
