import * as core from '@actions/core';
import * as path from 'path';
import { getInputs } from './config.js';
import { installAnalyzerCli } from './cli.js';
import { launchScan } from './scan.js';
import { downloadReport, downloadSbom } from './artifacts.js';

async function main() {
  try {
    const inputs = getInputs();
    core.setSecret(inputs.apiKey);

    const analyzerPath = installAnalyzerCli(inputs.cliVersion);

    const filePath = path.resolve(inputs.filePath);

    const scanId = launchScan(
      analyzerPath,
      inputs.apiKey,
      inputs.apiUrl,
      inputs.objectId,
      filePath,
      inputs.scanType,
      inputs.analysis,
    );

    core.setOutput('scan-id', scanId);

    const scanUrl = `${inputs.apiUrl.replace(/\/api\/?$/, '')}/objects/${inputs.objectId}/scans/${scanId}`;
    core.setOutput('scan-url', scanUrl);

    if (inputs.downloadReport) {
      const reportPath = downloadReport(analyzerPath, inputs.apiKey, inputs.apiUrl, scanId);
      if (reportPath) {
        core.setOutput('report-path', reportPath);
      }
    }

    if (inputs.downloadSbom) {
      const sbomPath = downloadSbom(analyzerPath, inputs.apiKey, inputs.apiUrl, scanId);
      if (sbomPath) {
        core.setOutput('sbom-path', sbomPath);
      }
    }

    core.info(`Scan complete: ${scanUrl}`);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    core.setFailed(msg);
  }
}

main();
