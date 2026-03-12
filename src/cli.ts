import * as core from '@actions/core';
import { execFileSync } from 'child_process';
import * as os from 'os';
import * as path from 'path';

const INSTALL_SCRIPT_URL = 'https://raw.githubusercontent.com/exein-io/analyzer-cli/main/dist/install.sh';

export function installAnalyzerCli(version: string): string {
  core.info(`Installing Analyzer CLI (${version})`);

  const scriptPath = path.join(os.tmpdir(), 'analyzer-install.sh');

  execFileSync('curl', ['-fsSL', '-o', scriptPath, INSTALL_SCRIPT_URL], {
    stdio: 'inherit',
  });

  const env: NodeJS.ProcessEnv = { ...process.env };
  if (version !== 'latest') {
    env.VERSION = version;
  }

  execFileSync('bash', [scriptPath], { stdio: 'inherit', env });

  const analyzerPath = execFileSync('which', ['analyzer'], {
    encoding: 'utf8',
  }).trim();

  core.info(`Analyzer CLI installed at ${analyzerPath}`);
  return analyzerPath;
}
