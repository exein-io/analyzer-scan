import * as core from '@actions/core';

export type ScanType = 'docker' | 'linux' | 'idf';

export interface Inputs {
  apiKey: string;
  apiUrl: string;
  objectId: string;
  scanType: ScanType;
  filePath: string;
  analysis: string[];
  downloadReport: boolean;
  downloadSbom: boolean;
  cliVersion: string;
}

const VALID_SCAN_TYPES: ScanType[] = ['docker', 'linux', 'idf'];

const VALID_ANALYSIS: Record<ScanType, string[]> = {
  docker: ['info', 'cve', 'password-hash', 'crypto', 'software-bom', 'malware', 'hardening', 'capabilities'],
  linux: [
    'info',
    'kernel',
    'cve',
    'password-hash',
    'crypto',
    'software-bom',
    'malware',
    'hardening',
    'capabilities',
  ],
  idf: ['info', 'cve', 'software-bom', 'symbols', 'tasks', 'stack-overflow'],
};

function parseListInput(input: string): string[] {
  return input
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function getInputs(): Inputs {
  const apiKey = core.getInput('api-key', { required: true });
  const apiUrl = core.getInput('api-url');
  const objectId = core.getInput('object-id', { required: true });
  const scanTypeRaw = core.getInput('scan-type', { required: true });
  const filePath = core.getInput('file-path', { required: true });
  const analysisRaw = parseListInput(core.getInput('analysis'));
  const downloadReport = core.getInput('download-report') === 'true';
  const downloadSbom = core.getInput('download-sbom') === 'true';
  const cliVersion = core.getInput('cli-version');

  // Validate scan type
  if (!VALID_SCAN_TYPES.includes(scanTypeRaw as ScanType)) {
    throw new Error(`Invalid scan-type "${scanTypeRaw}". Must be one of: ${VALID_SCAN_TYPES.join(', ')}`);
  }
  const scanType = scanTypeRaw as ScanType;

  // Validate and default analysis types
  let analysis = analysisRaw;
  if (analysis.length === 0) {
    analysis = VALID_ANALYSIS[scanType];
  } else {
    const valid = VALID_ANALYSIS[scanType];
    for (const a of analysis) {
      if (!valid.includes(a)) {
        throw new Error(
          `Invalid analysis type "${a}" for ${scanType} scans. Valid types: ${valid.join(', ')}`,
        );
      }
    }
  }

  return {
    apiKey,
    apiUrl,
    objectId,
    scanType,
    filePath,
    analysis,
    downloadReport,
    downloadSbom,
    cliVersion,
  };
}
