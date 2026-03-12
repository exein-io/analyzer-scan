import * as core from '@actions/core';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import type { ScanType } from './config.js';

export function launchScan(
  analyzerPath: string,
  apiKey: string,
  apiUrl: string,
  objectId: string,
  filePath: string,
  scanType: ScanType,
  analysis: string[],
): string {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Firmware image not found at path: ${filePath}`);
  }

  const args: string[] = [
    '--api-key',
    apiKey,
    '--url',
    apiUrl,
    '--format',
    'json',
    'scan',
    'new',
    '--object',
    objectId,
    '--file',
    filePath,
    '--type',
    scanType,
    '--analysis',
    ...analysis,
  ];

  core.info(`Launching ${scanType} scan on ${filePath}`);
  const cliOutput = execFileSync(analyzerPath, args, { encoding: 'utf8' });

  let parsedCliOutput: { id?: string };
  try {
    parsedCliOutput = JSON.parse(cliOutput);
  } catch {
    throw new Error(`Failed to parse Analyzer CLI JSON output:\n${cliOutput}`);
  }

  const scanId = parsedCliOutput.id;
  if (!scanId) {
    throw new Error(`Scan ID not found in Analyzer CLI output:\n${cliOutput}`);
  }

  core.info(`Scan created with ID: ${scanId}`);
  return scanId;
}
