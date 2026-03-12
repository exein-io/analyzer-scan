import * as core from '@actions/core';
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

function detectPlatform(): string {
  let osPart: string;
  switch (os.platform()) {
    case 'linux':
      osPart = 'unknown-linux-gnu';
      break;
    case 'darwin':
      osPart = 'apple-darwin';
      break;
    default:
      throw new Error(`Unsupported OS: ${os.platform()}`);
  }

  let archPart: string;
  switch (os.arch()) {
    case 'x64':
      archPart = 'x86_64';
      break;
    case 'arm64':
      archPart = 'aarch64';
      break;
    default:
      throw new Error(`Unsupported architecture: ${os.arch()}`);
  }

  return `${archPart}-${osPart}`;
}

export function installAnalyzerCli(version: string, apiKey: string, apiUrl: string): string {
  const platform = detectPlatform();
  core.info(`Installing Analyzer CLI (${version}) for ${platform}`);

  const base = apiUrl.replace(/\/$/, '');
  const url = `${base}/releases/analyzer-cli/${encodeURIComponent(version)}/analyzer-${platform}.tar.gz`;

  const installDir = path.join(os.tmpdir(), 'analyzer-cli');
  fs.mkdirSync(installDir, { recursive: true });
  const archivePath = path.join(installDir, 'analyzer.tar.gz');

  try {
    execFileSync('curl', ['-fsSL', '-H', `Authorization: Bearer ${apiKey}`, '-o', archivePath, url], {
      stdio: 'inherit',
    });
    execFileSync('tar', ['xzf', archivePath, '-C', installDir], { stdio: 'inherit' });
  } catch {
    throw new Error(`Failed to download Analyzer CLI ${version} for ${platform} from the platform`);
  }

  const analyzerPath = path.join(installDir, 'analyzer');
  fs.chmodSync(analyzerPath, 0o755);

  core.info(`Analyzer CLI installed at ${analyzerPath}`);
  return analyzerPath;
}
