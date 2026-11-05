import * as core from '@actions/core';
import { spawnCli } from './analyzer.js';
import { installAnalyzerCli } from './cli.js';
import { runGate, runStatus, runUpload, type Deps } from './gate.js';
import { parseInputs } from './inputs.js';

async function main() {
  try {
    const inputs = parseInputs(core.getInput);
    core.setSecret(inputs.apiKey);

    const analyzerPath = installAnalyzerCli(inputs.cliVersion, inputs.apiKey, inputs.apiUrl, core.info);
    const deps: Deps = {
      cli: spawnCli(analyzerPath, core.info),
      log: core,
      setOutput: core.setOutput,
      writeSummary: async (markdown) => {
        if (process.env.GITHUB_STEP_SUMMARY) {
          await core.summary.addRaw(markdown).write();
        }
      },
      outDir: process.cwd(),
      now: Date.now,
    };

    switch (inputs.mode) {
      case 'scan':
        await runUpload(inputs, deps);
        break;
      case 'status':
        await runStatus(inputs, deps);
        break;
      case 'gate': {
        const report = await runGate(inputs, deps);
        if (!report.passed) {
          core.setFailed(report.failures.join('\n') || `The gate failed for scan ${report['scan-id']}`);
        }
        break;
      }
    }
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

main();
