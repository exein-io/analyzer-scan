import { spawn } from 'child_process';
import * as path from 'path';
import * as readline from 'readline';
import { formatSeconds, type FailOn, type Upload } from './inputs.js';

/** The CVEs of one severity. */
export interface CveTiers {
  all: number;
  reachable: number;
  unreachable: number;
  unresolved: number;
}

/** The CVE counts of a scan, as the API answers them; the CLI passes them on as they are. */
export interface CveCounts {
  classification: string;
  settled: boolean;
  'checked-at': string;
  'catalog-as-of'?: string | null;
  critical: CveTiers;
  high: CveTiers;
  medium: CveTiers;
  low: CveTiers;
  unknown: CveTiers;
}

/** What `analyzer scan new --format json` prints. */
export interface NewScan {
  id: string;
  'object-id': string;
  /** The scan's page in the Analyzer UI. */
  url: string;
}

/** What `analyzer scan status --format json` prints. */
export interface ScanStatus {
  id: string;
  'object-id': string;
  /** `pending`, `in-progress`, `success`, `error` or `canceled`. */
  status: string;
  /** The scan ended: it succeeded, failed or was canceled. */
  finished: boolean;
}

/** What `analyzer scan gate --format json` prints when it decided, on exit 0 and 1. */
export interface GateReport {
  'scan-id': string;
  'object-id': string;
  url: string;
  status: string;
  'fail-on': FailOn;
  passed: boolean;
  /** Null when the scan has no counts. */
  blocking: number | null;
  'cve-counts': CveCounts | null;
  'no-counts-reason': string | null;
  /** Each null when that file is missing. */
  'sbom-path': string | null;
  'vex-path': string | null;
  'report-path': string | null;
  /** One line per reason the gate failed; empty when it passed. */
  failures: string[];
  /** Why the report is missing. */
  warnings: string[];
}

/** How the action connects the CLI: by environment, so the key stays out of the process list. */
export interface CliEnv {
  ANALYZER_API_KEY: string;
  ANALYZER_URL: string;
}

export interface CliCall {
  args: string[];
  env: CliEnv;
  /** Stops the CLI when it runs longer than this. No limit when unset. */
  timeoutSeconds?: number;
}

export interface CliExit {
  code: number;
  stdout: string;
}

/** Runs the Analyzer CLI once, to its exit. */
export type CliRunner = (call: CliCall) => Promise<CliExit>;

/** Done; for `scan gate`, the gate passed. */
export const EXIT_DONE = 0;
/** `scan gate` only: the gate failed. */
export const EXIT_GATE_FAILED = 1;

/** The CLI gave no result: its error, or an exit code outside the contract. */
export class CliError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

export function cliEnv(apiKey: string, apiUrl: string): CliEnv {
  return { ANALYZER_API_KEY: apiKey, ANALYZER_URL: apiUrl.replace(/\/+$/, '') };
}

/**
 * Runs the CLI at `analyzerPath`. Its stderr is its progress, passed to `log` line by line as it comes, so
 * a wait of hours shows in the job log. Its stdout is kept for the JSON document it ends with.
 */
export function spawnCli(analyzerPath: string, log: (line: string) => void): CliRunner {
  return ({ args, env, timeoutSeconds }) =>
    new Promise((resolve, reject) => {
      const child = spawn(analyzerPath, args, {
        env: { ...process.env, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      let stopped: Error | undefined;
      const timer =
        timeoutSeconds === undefined
          ? undefined
          : setTimeout(() => {
              stopped = new Error(
                `The Analyzer CLI did not exit within ${formatSeconds(timeoutSeconds)}, so the action stopped it`,
              );
              child.kill('SIGKILL');
            }, timeoutSeconds * 1000);
      const stdout: Buffer[] = [];
      child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
      readline.createInterface({ input: child.stderr, crlfDelay: Infinity }).on('line', log);
      child.on('error', (err) => {
        clearTimeout(timer);
        reject(
          new Error(`Could not run the Analyzer CLI at ${analyzerPath}: ${err.message}`, { cause: err }),
        );
      });
      child.on('close', (code, signal) => {
        clearTimeout(timer);
        if (stopped) {
          reject(stopped);
        } else if (code === null) {
          reject(new Error(`The Analyzer CLI was stopped by ${signal}`));
        } else {
          resolve({ code, stdout: Buffer.concat(stdout).toString('utf8') });
        }
      });
    });
}

function parseJson(stdout: string): unknown {
  try {
    return JSON.parse(stdout);
  } catch {
    return undefined;
  }
}

/** Runs a command with `--format json`, and returns its JSON document when it exits with one of `codes`. */
async function run(
  cli: CliRunner,
  env: CliEnv,
  args: string[],
  codes: number[],
  timeoutSeconds?: number,
): Promise<CliExit & { json: unknown }> {
  const command = `analyzer ${args.slice(0, 2).join(' ')}`;
  const exit = await cli({ args: [...args, '--format', 'json'], env, timeoutSeconds });
  const json = parseJson(exit.stdout);
  const output = exit.stdout.trim().slice(0, 1000);
  if (!codes.includes(exit.code)) {
    const error = (json as { error?: unknown } | undefined)?.error;
    throw new CliError(
      exit.code,
      typeof error === 'string' ? error : `${command} exited ${exit.code}${output ? `: ${output}` : ''}`,
    );
  }
  if (typeof json !== 'object' || json === null) {
    throw new CliError(
      exit.code,
      `${command} exited ${exit.code} without its JSON output${output ? `: ${output}` : ''}`,
    );
  }
  return { ...exit, json };
}

function scanNewArgs(upload: Upload): string[] {
  const object =
    'id' in upload.object
      ? ['--object', upload.object.id]
      : [
          '--object-key',
          upload.object.key,
          ...(upload.object.name ? ['--object-name', upload.object.name] : []),
        ];
  return [
    'scan',
    'new',
    ...object,
    '--file',
    path.resolve(upload.filePath),
    '--type',
    upload.scanType,
    ...(upload.buildVex ? ['--vex', path.resolve(upload.buildVex)] : []),
  ];
}

/** `analyzer scan new`: uploads the image, which starts a scan. The runner stops it after `timeoutSeconds`. */
export async function scanNew(
  cli: CliRunner,
  env: CliEnv,
  upload: Upload,
  timeoutSeconds?: number,
): Promise<NewScan> {
  const { json } = await run(cli, env, scanNewArgs(upload), [EXIT_DONE], timeoutSeconds);
  const scan = json as NewScan;
  if (typeof scan.id !== 'string') {
    throw new CliError(EXIT_DONE, `analyzer scan new printed no scan id: ${JSON.stringify(json)}`);
  }
  return scan;
}

/**
 * `analyzer scan status`: one read of the scan, with the CLI's retries. The command takes no --timeout, so
 * the runner stops it after `timeoutSeconds`.
 */
export async function scanStatus(
  cli: CliRunner,
  env: CliEnv,
  scanId: string,
  timeoutSeconds: number,
): Promise<ScanStatus> {
  const { json } = await run(cli, env, ['scan', 'status', '--scan', scanId], [EXIT_DONE], timeoutSeconds);
  const scan = json as ScanStatus;
  if (typeof scan.status !== 'string' || typeof scan.finished !== 'boolean') {
    throw new CliError(EXIT_DONE, `analyzer scan status printed no status: ${JSON.stringify(json)}`);
  }
  return scan;
}

export interface GateArgs {
  scanId: string;
  failOn: FailOn;
  timeoutSeconds: number;
  outDir: string;
}

function scanGateArgs({ scanId, failOn, timeoutSeconds, outDir }: GateArgs): string[] {
  // Whole seconds, so the CLI reads the duration exactly as the action did.
  return [
    'scan',
    'gate',
    '--scan',
    scanId,
    '--fail-on',
    failOn,
    '--timeout',
    `${timeoutSeconds}s`,
    '--out-dir',
    outDir,
  ];
}

/**
 * `analyzer scan gate`: waits for the scan and its CVE classification, downloads the SBOM, VEX and report,
 * and decides. The exit code is the decision, so `passed` follows it.
 */
export async function scanGate(cli: CliRunner, env: CliEnv, args: GateArgs): Promise<GateReport> {
  const { code, json } = await run(cli, env, scanGateArgs(args), [EXIT_DONE, EXIT_GATE_FAILED]);
  const report = json as GateReport;
  if (typeof report.passed !== 'boolean' || !Array.isArray(report.failures)) {
    throw new CliError(code, `analyzer scan gate printed no decision: ${JSON.stringify(json)}`);
  }
  return { ...report, passed: code === EXIT_DONE, warnings: report.warnings ?? [] };
}
