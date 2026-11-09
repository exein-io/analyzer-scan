import * as core from '@actions/core';
import { spawnCli } from './analyzer.js';
import { installAnalyzerCli } from './cli.js';
import { runMode, type Deps } from './gate.js';
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
      setFailed: core.setFailed,
    };

    await runMode(inputs, deps);
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

main();
