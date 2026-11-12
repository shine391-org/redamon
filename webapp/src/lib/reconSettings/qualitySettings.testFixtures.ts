export const qualitySettings = {
  nucleiRoutingMode: 'enforce', jsReconFetchAdmission: false, arjunLateSources: false,
  chunkCheckpointEnabled: false, checkpointBudgetPerGroup: 0, checkpointBudgetPerTool: 1000000,
}
export const invalidQualitySettings: [string, unknown][] = [
  ...['invalid', 'SHADOW', '', null, 0, false, [], {}].map(v => ['nucleiRoutingMode', v] as [string, unknown]),
  ...['jsReconFetchAdmission', 'arjunLateSources', 'chunkCheckpointEnabled'].flatMap(k =>
    ['true', 'false', null, 0, 1, [], {}].map(v => [k, v] as [string, unknown])),
  ...['checkpointBudgetPerGroup', 'checkpointBudgetPerTool'].flatMap(k =>
    ['0', '1', null, -1, 1000001, 0.5, true, [], {}].map(v => [k, v] as [string, unknown])),
  ['NUCLEI_ROUTING_MODE', 'off'], ['JS_RECON_FETCH_ADMISSION', true],
  ['CHECKPOINT_BUDGET_PER_GROUP', 0],
]
