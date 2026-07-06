import * as core from '@actions/core';

export type ScanType = 'docker' | 'linux' | 'idf' | 'sbom';

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

const VALID_SCAN_TYPES: ScanType[] = ['docker', 'linux', 'idf', 'sbom'];

const ANALYSES_BY_TYPE: Record<ScanType, string[]> = {
  docker: ['info', 'cve', 'password-hash', 'crypto', 'sbom', 'malware', 'hardening', 'capabilities'],
  linux: ['info', 'kernel', 'cve', 'password-hash', 'crypto', 'sbom', 'malware', 'hardening', 'capabilities'],
  idf: ['info', 'cve', 'sbom', 'symbols', 'tasks', 'stack-overflow'],
  sbom: ['cve', 'sbom'],
};

export function getInputs(): Inputs {
  const apiKey = core.getInput('api-key', { required: true });
  const apiUrl = core.getInput('api-url');
  const objectId = core.getInput('object-id', { required: true });
  const scanTypeRaw = core.getInput('scan-type', { required: true });
  const filePath = core.getInput('file-path', { required: true });
  const downloadReport = core.getInput('download-report') === 'true';
  const downloadSbom = core.getInput('download-sbom') === 'true';
  const cliVersion = core.getInput('cli-version');

  // Validate scan type
  if (!VALID_SCAN_TYPES.includes(scanTypeRaw as ScanType)) {
    throw new Error(`Invalid scan-type "${scanTypeRaw}". Must be one of: ${VALID_SCAN_TYPES.join(', ')}`);
  }
  const scanType = scanTypeRaw as ScanType;

  const analysis = ANALYSES_BY_TYPE[scanType];

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
