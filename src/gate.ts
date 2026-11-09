import * as path from 'path';
import {
  cliEnv,
  scanGate,
  scanNew,
  scanStatus,
  type CliRunner,
  type GateReport,
  type NewScan,
  type ScanStatus,
} from './analyzer.js';
import {
  FAIL_ON_SEVERITIES,
  formatSeconds,
  type FailOn,
  type GateInputs,
  type Inputs,
  type ScanInputs,
  type Severity,
  type StatusInputs,
  type Upload,
} from './inputs.js';

export interface Logger {
  info(message: string): void;
  warning(message: string): void;
}

export interface Deps {
  cli: CliRunner;
  log: Logger;
  setOutput(name: string, value: string): void;
  writeSummary(markdown: string): Promise<void>;
  /** Where the SBOM, VEX and report land. */
  outDir: string;
  /** Milliseconds, as `Date.now`. */
  now(): number;
  /** Fails the step, as `core.setFailed`. */
  setFailed(message: string): void;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** The time a step has left of its `timeout`, counted from its start. */
class Deadline {
  private readonly end: number;

  constructor(
    private readonly deps: Deps,
    private readonly timeoutSeconds: number,
  ) {
    this.end = deps.now() + timeoutSeconds * 1000;
  }

  /**
   * Whole seconds left; throws when none are, with how to gate the scan later. When the CLI's own
   * --timeout runs out instead, its error already names the scan and how to gate it later.
   */
  secondsLeft(scanId: string): number {
    const left = Math.floor((this.end - this.deps.now()) / 1000);
    if (left < 1) {
      throw new Error(
        `The timeout of ${formatSeconds(this.timeoutSeconds)} ran out before scan ${scanId} finished. ` +
          `To gate this scan later, run the gate with scan-id: ${scanId}`,
      );
    }
    return left;
  }
}

/** Outputs the scan as soon as it exists, so a later failure still leaves its id. */
function announce(scan: NewScan, deps: Deps) {
  deps.setOutput('scan-id', scan.id);
  deps.setOutput('object-id', scan['object-id']);
  deps.setOutput('scan-url', scan.url);
}

/** Writes the error summary, and throws the error. */
async function fail(err: unknown, deps: Deps, link?: string): Promise<never> {
  await deps.writeSummary(renderErrorSummary(errorMessage(err), link));
  throw err;
}

/**
 * `gate: false`: uploads the image, which starts a scan, and returns without waiting. A later step gates the
 * scan with `gate: true` and its `scan-id`, or the gate waits for it from the start with `fail-on: none`.
 */
export async function runUpload(inputs: ScanInputs, deps: Deps): Promise<NewScan> {
  let scan: NewScan;
  try {
    scan = await scanNew(deps.cli, cliEnv(inputs.apiKey, inputs.apiUrl), inputs.upload);
  } catch (err) {
    return fail(err, deps);
  }
  announce(scan, deps);
  await deps.writeSummary(renderUploadSummary(inputs.upload, scan));
  return scan;
}

/** Runs the mode the inputs ask for. A gate that does not pass fails the step. */
export async function runMode(inputs: Inputs, deps: Deps): Promise<NewScan | GateReport | ScanStatus> {
  switch (inputs.mode) {
    case 'scan':
      return runUpload(inputs, deps);
    case 'status':
      return runStatus(inputs, deps);
    case 'gate': {
      const report = await runGate(inputs, deps);
      if (!report.passed) {
        deps.setFailed(report.failures.join('\n') || `The gate failed for scan ${report['scan-id']}`);
      }
      return report;
    }
  }
}

/**
 * `gate: true`: uploads the image (or takes a scan made earlier), then runs `analyzer scan gate`, which waits
 * until the scan finishes and its CVE classification settles, downloads the SBOM, VEX and report, and decides.
 */
export async function runGate(inputs: GateInputs, deps: Deps): Promise<GateReport> {
  const deadline = new Deadline(deps, inputs.timeoutSeconds);
  const env = cliEnv(inputs.apiKey, inputs.apiUrl);
  let link: string | undefined;
  try {
    let scanId: string;
    if ('scanId' in inputs.target) {
      scanId = inputs.target.scanId;
      deps.setOutput('scan-id', scanId);
    } else {
      // The timeout counts the upload, so the runner stops an upload that stalls.
      const made = await scanNew(deps.cli, env, inputs.target, inputs.timeoutSeconds);
      announce(made, deps);
      scanId = made.id;
      link = made.url;
    }
    const report = await scanGate(deps.cli, env, {
      scanId,
      failOn: inputs.failOn,
      timeoutSeconds: deadline.secondsLeft(scanId),
      outDir: deps.outDir,
    });
    deps.setOutput('object-id', report['object-id']);
    deps.setOutput('scan-url', report.url);
    deps.setOutput('scan-status', report.status);
    if (report['cve-counts']) {
      deps.setOutput('cve-counts', JSON.stringify(report['cve-counts']));
    }
    if (typeof report.blocking === 'number') {
      deps.setOutput('blocking', String(report.blocking));
    }
    for (const output of ['sbom-path', 'vex-path', 'report-path'] as const) {
      const file = report[output];
      if (file) {
        deps.setOutput(output, file);
      }
    }
    await deps.writeSummary(renderSummary(report));
    return report;
  } catch (err) {
    return fail(err, deps, link);
  }
}

/**
 * The longest `gate: status` lets the CLI run. The CLI gives up on its own after 15 minutes of errors in a
 * row, so this only stops a CLI that hangs.
 */
export const STATUS_TIMEOUT_SECONDS = 20 * 60;

/**
 * `gate: status`: reads the status of a scan made earlier, once. A scan that ended in `error` or was
 * `canceled` does not fail the step. The step only reports, and the gate decides.
 */
export async function runStatus(inputs: StatusInputs, deps: Deps): Promise<ScanStatus> {
  deps.setOutput('scan-id', inputs.scanId);
  const scan = await scanStatus(
    deps.cli,
    cliEnv(inputs.apiKey, inputs.apiUrl),
    inputs.scanId,
    Math.min(inputs.timeoutSeconds, STATUS_TIMEOUT_SECONDS),
  );
  deps.setOutput('object-id', scan['object-id']);
  deps.setOutput('scan-status', scan.status);
  deps.setOutput('finished', String(scan.finished));
  deps.log.info(`Scan ${scan.id}: status ${scan.status}, ${scan.finished ? 'finished' : 'not finished'}`);
  await deps.writeSummary(renderStatusSummary(scan));
  return scan;
}

/** The severities at or above `failOn`; none for `none`, which only reports. */
function gatedSeverities(failOn: FailOn): Severity[] {
  if (failOn === 'none') {
    return [];
  }
  return FAIL_ON_SEVERITIES.slice(0, FAIL_ON_SEVERITIES.indexOf(failOn) + 1);
}

const SEVERITY_ROWS = [...FAIL_ON_SEVERITIES, 'unknown'] as const;

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** The job summary: the decision and why, and a table of the counts per severity. */
export function renderSummary(report: GateReport): string {
  const failOn = report['fail-on'];
  const counts = report['cve-counts'];
  const lines = [`## Exein Analyzer release gate: ${report.passed ? 'passed' : 'failed'}`, ''];
  if (failOn === 'none') {
    lines.push("fail-on `none`: report only, CVEs don't fail the step.", '');
  } else if (report.passed) {
    lines.push(`No CVEs at fail-on \`${failOn}\` or above are reachable or unresolved.`, '');
  }
  if (report.failures.length > 0) {
    lines.push(...report.failures.map((f) => `- ${f}`), '');
  }
  if (!counts) {
    const reason = report['no-counts-reason'];
    lines.push(`The scan has no CVE counts${reason ? `: ${reason}` : '.'}`, '');
  }

  let scanLine = `Scan [${report['scan-id']}](${report.url}), status \`${report.status}\`.`;
  if (counts) {
    scanLine +=
      ` Classification \`${counts.classification}\`${counts.settled ? '' : ', not settled'}, ` +
      `checked at ${counts['checked-at']}${counts['catalog-as-of'] ? `, catalog as of ${counts['catalog-as-of']}` : ''}.`;
  }
  lines.push(scanLine);
  if (counts) {
    const gated = new Set<string>(gatedSeverities(failOn));
    lines.push(
      '',
      '| Severity | All | Reachable | Unreachable | Unresolved | Blocking |',
      '|---|---:|---:|---:|---:|---:|',
      ...SEVERITY_ROWS.map((s) => {
        const t = counts[s];
        const blocks = t.reachable + t.unresolved;
        const cell = !gated.has(s) ? 'not gated' : blocks > 0 ? `**${blocks}**` : '0';
        return `| ${capitalize(s)} | ${t.all} | ${t.reachable} | ${t.unreachable} | ${t.unresolved} | ${cell} |`;
      }),
    );
    if (counts.classification === 'not-applicable') {
      lines.push(
        '',
        'This scan has no reachability classification, so each of its CVEs counts as unresolved.',
      );
    }
  }
  if (!report['report-path']) {
    // The CLI's warnings name the missing report and why.
    const why = report.warnings.length > 0 ? report.warnings.join('; ') : 'The PDF report is missing';
    lines.push('', `${why}. The gate does not need it.`);
  }
  return lines.join('\n') + '\n';
}

function objectName(upload: Upload): string {
  return 'id' in upload.object ? upload.object.id : upload.object.key;
}

export function renderUploadSummary(upload: Upload, scan: NewScan): string {
  return [
    '## Exein Analyzer upload',
    '',
    `Uploaded \`${path.basename(upload.filePath)}\` to object \`${objectName(upload)}\`: scan [${scan.id}](${scan.url}).`,
    '',
    `Gate it later with \`gate: 'true'\` and \`scan-id: ${scan.id}\`.`,
    '',
  ].join('\n');
}

export function renderStatusSummary(scan: ScanStatus): string {
  return `Exein Analyzer scan \`${scan.id}\`: status \`${scan.status}\`, ${scan.finished ? 'finished' : 'not finished'}.\n`;
}

export function renderErrorSummary(message: string, link?: string): string {
  return ['## Exein Analyzer: error', '', message, ...(link ? ['', `[The scan](${link})`] : []), ''].join(
    '\n',
  );
}
