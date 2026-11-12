import type { Project } from '@prisma/client'

/**
 * Minimal fallback defaults - only required fields. Full defaults are fetched
 * from /api/projects/defaults (served by recon backend). Every form state is
 * built on top of these, edit mode included.
 */
export const MINIMAL_DEFAULTS: Partial<Project> = {
  plannerMode: 'off',
  plannerManifestEnabled: false,
  plannerConsumerAiTags: false,
  plannerConsumerTargetSelection: false,
  plannerConsumerTwoPass: false,
  nucleiRoutingMode: 'off',
  jsReconFetchAdmission: true,
  arjunLateSources: true,
  chunkCheckpointEnabled: true,
  checkpointBudgetPerGroup: 0,
  checkpointBudgetPerTool: 0,
  name: '',
  jevProviderId: null,
  description: '',
  targetDomain: '',
  subdomainList: [],
  ipMode: false,
  targetIps: [],
  domainBatchMode: false,
  domainBatchHosts: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
}
