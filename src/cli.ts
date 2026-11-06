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

/** The platform serves the CLI under the API root, `/api`, also when `api-url` is the `/api/v2` form. */
export function cliDownloadUrl(apiUrl: string, version: string, platform: string): string {
  const root = apiUrl.replace(/\/+$/, '').replace(/\/api\/v2$/, '/api');
  return `${root}/releases/analyzer-cli/${encodeURIComponent(version)}/analyzer-${platform}.tar.gz`;
}

export function installAnalyzerCli(
  version: string,
  apiKey: string,
  apiUrl: string,
  info: (message: string) => void,
): string {
  const platform = detectPlatform();
  info(`Installing Analyzer CLI (${version}) for ${platform}`);

  const url = cliDownloadUrl(apiUrl, version, platform);

  const installDir = path.join(os.tmpdir(), 'analyzer-cli');
  fs.mkdirSync(installDir, { recursive: true });
  const archivePath = path.join(installDir, 'analyzer.tar.gz');

  try {
    // The header goes in on stdin (-H @-), so the key stays out of the process list.
    execFileSync('curl', ['-fsSL', '-H', '@-', '-o', archivePath, url], {
      input: `Authorization: Bearer ${apiKey}\n`,
      stdio: ['pipe', 'inherit', 'inherit'],
    });
    execFileSync('tar', ['xzf', archivePath, '-C', installDir], { stdio: 'inherit' });
  } catch {
    throw new Error(`Failed to download Analyzer CLI ${version} for ${platform} from the platform`);
  }

  const analyzerPath = path.join(installDir, 'analyzer');
  fs.chmodSync(analyzerPath, 0o755);

  info(`Analyzer CLI installed at ${analyzerPath}`);
  return analyzerPath;
}
