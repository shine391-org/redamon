/**
 * Types for Recon Process Management
 */

export type ReconStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface ReconState {
  project_id: string
  status: ReconStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export interface ReconLogEvent {
  log: string
  timestamp: string
  phase?: string | null
  phaseNumber?: number | null
  isPhaseStart?: boolean
  level: 'info' | 'warning' | 'error' | 'success' | 'action'
}

export interface ReconSSEEvent {
  event: 'log' | 'error' | 'complete'
  data: ReconLogEvent | { error: string } | { status: string; completedAt?: string; error?: string }
}

// =============================================================================
// GVM Vulnerability Scan Types
// =============================================================================

export type GvmStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface GvmState {
  project_id: string
  status: GvmStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

// Kept in step with GVM_PHASE_PATTERNS in container_manager.py, in order: the
// drawer's "Phase N/M" takes M from here and N from the pattern's number.
// recon-types.phases.test.ts compares the three phase lists below with the Python.
export const GVM_PHASES = [
  'Loading Recon Data',
  'Waiting for GVM',
  'Connected to GVM',
  'Scanning IPs',
  'Scanning Hostnames',
] as const

export type GvmPhase = typeof GVM_PHASES[number]

// =============================================================================
// GitHub Secret Hunt Types
// =============================================================================

export type GithubHuntStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface GithubHuntState {
  project_id: string
  status: GithubHuntStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

// Kept in step with GITHUB_HUNT_PHASE_PATTERNS in container_manager.py.
export const GITHUB_HUNT_PHASES = [
  'Loading Settings',
  'Scanning Repositories',
  'Complete',
] as const

export type GithubHuntPhase = typeof GITHUB_HUNT_PHASES[number]

// =============================================================================
// TruffleHog Secret Scan Types
// =============================================================================

export type TrufflehogStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface TrufflehogState {
  project_id: string
  status: TrufflehogStatus
  /** The source id, which is ALSO the run key: one run per source, any number
   *  of distinct sources in parallel. */
  source?: string
  run_id?: string
  /** Human descriptor of what this run scans (org, image ref, bucket, URL). */
  target?: string
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
  /** Set once the clean ingest step has written the findings to the graph. */
  ingested?: boolean
  findings_count?: number
}

/** The /trufflehog/{projectId}/all payload. */
export interface TrufflehogListResponse {
  project_id: string
  runs: TrufflehogState[]
}

// Supply-Chain scan (L1 "Other Scans") - same lifecycle shape as trufflehog.
export type SupplyChainStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface SupplyChainState {
  project_id: string
  status: SupplyChainStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

// Kept in step with TRUFFLEHOG_PHASE_PATTERNS in container_manager.py. The
// scanner reads a job file rather than fetching settings, and it scans far more
// than repositories, so the old labels described neither.
export const TRUFFLEHOG_PHASES = [
  'Preparing',
  'Scanning',
  'Complete',
] as const

export type TrufflehogPhase = typeof TRUFFLEHOG_PHASES[number]

// =============================================================================
// Partial Recon Types
// =============================================================================

export type PartialReconStatus = 'idle' | 'starting' | 'running' | 'completed' | 'error' | 'stopping'

export interface PartialReconState {
  project_id: string
  run_id: string
  tool_id: string
  status: PartialReconStatus
  container_id: string | null
  started_at: string | null
  completed_at: string | null
  error: string | null
  stats: Record<string, number> | null
  /** The project roots the orchestrator started this run over. */
  roots?: string[]
}

export interface PartialReconListResponse {
  project_id: string
  runs: PartialReconState[]
}

export interface GraphInputs {
  /** The first root in `domains`, for callers that predate multi-root runs. */
  domain: string | null
  /** The project's current roots this tool can run over, sorted. A Domain-batch
   *  project has several; single-domain and IP mode have one. */
  domains?: string[]
  /** Domain nodes still in the graph that are no longer project roots. Never scanned. */
  stale_domains?: string[]
  /** Roots in `domains` with no recon data in the graph yet. */
  empty_domains?: string[]
  /** Domain nodes built under the old scope model (§4.11.6); non-empty means
   *  partial recon is refused until a full recon rebuilds the graph. */
  legacy_graph?: string[]
  /** SubdomainDiscovery only: the roots allowed to enumerate (a batch group
   *  enumerates only when the operator wrote a wildcard for it). */
  discovery_domains?: string[]
  existing_subdomains_count: number
  existing_subdomains?: string[]
  existing_ips_count?: number
  existing_ports_count?: number
  existing_baseurls_count?: number
  existing_baseurls?: string[]
  existing_endpoints_count?: number
  existing_graphql_endpoints_count?: number
  existing_ai_endpoints_count?: number
  existing_mcp_endpoints_count?: number
  existing_vector_db_services_count?: number
  existing_external_domains_count?: number
  fronted_count?: number
  /** OpenAPI only: the last runs' per-document status ("<id>|<url hash>|<code>|<time>"); null when unreadable. */
  openapiSourceStatus?: string[] | null
  source: 'graph' | 'settings'
}

export interface UserTargets {
  subdomains: string[]
  ips: string[]
  ip_attach_to: string | null
  ports?: number[]
  urls?: string[]
  url_attach_to?: string | null
}

export interface PartialReconParams {
  tool_id: string
  /** `{ domains: [...] }`. A job queued before multi-root runs carries `{ domain }`. */
  graph_inputs: Record<string, string | string[]>
  user_inputs: string[]
  user_targets?: UserTargets
  include_graph_targets?: boolean
  settings_overrides?: Record<string, unknown>
}

/** The only settings a partial run may override (the Nuclei checkboxes). The
 *  orchestrator answers 400 to anything else. Mirrors PARTIAL_OVERRIDE_KEYS in
 *  recon_orchestrator/batch_scope.py. */
export const PARTIAL_RECON_OVERRIDE_KEYS = ['CVE_LOOKUP_ENABLED', 'MITRE_ENABLED', 'SECURITY_CHECK_ENABLED'] as const

export const PARTIAL_RECON_SUPPORTED_TOOLS = new Set(['SubdomainDiscovery', 'Naabu', 'Masscan', 'Nmap', 'Tlsx', 'Httpx', 'IpAttribution', 'Katana', 'OpenAPI', 'ZapAjaxSpider', 'Hakrawler', 'Jsluice', 'Gau', 'Kiterunner', 'ParamSpider', 'Arjun', 'Ffuf', 'EndpointAiClassifier', 'AiSurfaceRecon', 'JsRecon', 'SerializedScan', 'RouteExposure', 'SupplyChainRecon', 'GraphqlScan', 'Nuclei', 'SubdomainTakeover', 'VhostSni', 'WebCachePoison', 'SecurityChecks', 'Shodan', 'Urlscan', 'Uncover', 'OsintEnrichment', 'OriginDiscovery'])

/**
 * A partial run's phase count. The orchestrator pins every partial-run log
 * event to phase 1 (stream_partial_logs in container_manager.py): the phase
 * NAME comes from the full pipeline's patterns, the number is always 1 of 1.
 * recon-types.phases.test.ts checks the pin.
 */
export const PARTIAL_RECON_TOTAL_PHASES = 1

/**
 * The full pipeline's phase count: the last number PHASE_PATTERNS assigns
 * (1-6, with an AI Surface Recon 4.5 between 4 and 5), as ReconState.total_phases
 * says. recon-types.phases.test.ts checks it.
 */
export const RECON_TOTAL_PHASES = 6
