import * as core from '@actions/core';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const INSTALL_SCRIPT_URL = 'https://raw.githubusercontent.com/exein-io/analyzer-cli/main/dist/install.sh';

export function installAnalyzerCli(version: string): string {
  core.info(`Installing Analyzer CLI (${version})`);

  const scriptPath = path.join(os.tmpdir(), 'analyzer-install.sh');

  execFileSync('curl', ['-fsSL', '-o', scriptPath, INSTALL_SCRIPT_URL], {
    stdio: 'inherit',
  });

  const content = fs.readFileSync(scriptPath, 'utf8');
  if (!content.startsWith('#!/')) {
    throw new Error(`Downloaded install script appears invalid:\n${content.slice(0, 200)}`);
  }

  const installDir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzer-'));

  const env: NodeJS.ProcessEnv = { ...process.env, INSTALL_DIR: installDir };
  if (version !== 'latest') {
    env.VERSION = version;
  }

  // The upstream install script has a bug where the EXIT trap references a
  // local variable under set -u, causing a non-zero exit even on success.
  // See: https://github.com/exein-io/analyzer-cli/pull/XXX
  try {
    execFileSync('bash', [scriptPath], { stdio: 'inherit', env });
  } catch {
    // Verify the binary was actually installed despite the exit code
  }

  const analyzerPath = path.join(installDir, 'analyzer');
  if (!fs.existsSync(analyzerPath)) {
    throw new Error(`Analyzer CLI binary not found at ${analyzerPath}`);
  }

  core.info(`Analyzer CLI installed at ${analyzerPath}`);
  return analyzerPath;
}
