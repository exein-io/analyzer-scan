import * as core from '@actions/core';
import { execFileSync } from 'child_process';
import * as path from 'path';

function downloadArtifact(
  analyzerPath: string,
  apiKey: string,
  apiUrl: string,
  scanId: string,
  subcommand: string,
  outputFile: string,
): string | null {
  const outputPath = path.resolve(outputFile);

  try {
    core.info(`Downloading ${subcommand}...`);
    execFileSync(
      analyzerPath,
      [
        '--api-key',
        apiKey,
        '--url',
        apiUrl,
        'scan',
        subcommand,
        '--scan',
        scanId,
        '--output',
        outputPath,
        '--wait',
      ],
      { encoding: 'utf8' },
    );
    core.info(`${subcommand} downloaded to ${outputPath}`);
    return outputPath;
  } catch (err) {
    core.warning(`Failed to download ${subcommand}: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

export function downloadReport(
  analyzerPath: string,
  apiKey: string,
  apiUrl: string,
  scanId: string,
): string | null {
  return downloadArtifact(analyzerPath, apiKey, apiUrl, scanId, 'report', 'report.pdf');
}

export function downloadSbom(
  analyzerPath: string,
  apiKey: string,
  apiUrl: string,
  scanId: string,
): string | null {
  return downloadArtifact(analyzerPath, apiKey, apiUrl, scanId, 'sbom', 'sbom.json');
}
