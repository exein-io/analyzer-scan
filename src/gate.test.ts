import assert from 'node:assert/strict';
import * as path from 'path';
import { before, describe, it } from 'node:test';
import type { CliCall, CliRunner, CveCounts, CveTiers, GateReport, NewScan, ScanStatus } from './analyzer.js';
import { renderErrorSummary, renderStatusSummary, renderSummary, runMode, type Deps } from './gate.js';
import type { GateInputs, Inputs, ScanInputs, StatusInputs, Upload } from './inputs.js';

const OBJECT_ID = '11111111-1111-4111-8111-111111111111';
const SCAN_ID = '22222222-2222-4222-8222-222222222222';
const SCAN_URL = `https://analyzer.example.com/objects/${OBJECT_ID}/scans/${SCAN_ID}`;
const OUT_DIR = '/work';

const tiers = (t: Partial<CveTiers> = {}): CveTiers => ({
  all: 0,
  reachable: 0,
  unreachable: 0,
  unresolved: 0,
  ...t,
});

const counts = (c: Partial<CveCounts> = {}): CveCounts => ({
  classification: 'settled',
  settled: true,
  'checked-at': '2026-11-05T10:00:00Z',
  critical: tiers(),
  high: tiers(),
  medium: tiers(),
  low: tiers(),
  unknown: tiers(),
  ...c,
});

/** One high CVE that is reachable: blocks at fail-on high, not at critical. */
const ONE_HIGH = counts({ high: tiers({ all: 1, reachable: 1 }) });

const NEW_SCAN: NewScan = { id: SCAN_ID, 'object-id': OBJECT_ID, url: SCAN_URL };

/** What `scan status` prints. */
const scanStatus = (status: string, finished: boolean): ScanStatus => ({
  id: SCAN_ID,
  'object-id': OBJECT_ID,
  status,
  finished,
});

const EVIDENCE = {
  'sbom-path': `${OUT_DIR}/${SCAN_ID}-sbom.json`,
  'vex-path': `${OUT_DIR}/${SCAN_ID}-vex.json`,
  'report-path': `${OUT_DIR}/${SCAN_ID}-report.pdf`,
};

/** What `scan gate` prints for a scan that is done, with ONE_HIGH, at fail-on critical. */
const report = (r: Partial<GateReport> = {}): GateReport => ({
  'scan-id': SCAN_ID,
  'object-id': OBJECT_ID,
  url: SCAN_URL,
  status: 'success',
  'fail-on': 'critical',
  passed: true,
  blocking: 0,
  'cve-counts': ONE_HIGH,
  'no-counts-reason': null,
  ...EVIDENCE,
  failures: [],
  warnings: [],
  ...r,
});

/** What the CLI does for one command. */
interface Reply {
  code: number;
  /** Printed to stdout as JSON. */
  json?: unknown;
  /** Printed to stdout as it is, instead of `json`. */
  stdout?: string;
  /** How long the command runs, on the test's clock. */
  takesMs?: number;
}

const done = (json: unknown): Reply => ({ code: 0, json });
const gateFailed = (json: unknown): Reply => ({ code: 1, json });
const noResult = (error: string): Reply => ({ code: 2, json: { error } });

const CONNECTION = {
  apiKey: 'test-key',
  apiUrl: 'https://analyzer.example.com/api/',
  cliVersion: 'v1.0.0',
};

const BY_KEY: Upload = {
  object: { key: 'gateway-firmware', name: 'Gateway firmware' },
  scanType: 'linux',
  filePath: 'build/image.tar',
  buildVex: 'build/image.vex.json',
};

const BY_ID: Upload = { object: { id: OBJECT_ID }, scanType: 'docker', filePath: 'image.tar' };

const gate = (i: Partial<GateInputs> = {}): GateInputs => ({
  ...CONNECTION,
  mode: 'gate',
  failOn: 'critical',
  target: BY_KEY,
  timeoutSeconds: 19_800,
  ...i,
});

const scan = (i: Partial<ScanInputs> = {}): ScanInputs => ({
  ...CONNECTION,
  mode: 'scan',
  upload: BY_ID,
  ...i,
});

const status = (i: Partial<StatusInputs> = {}): StatusInputs => ({
  ...CONNECTION,
  mode: 'status',
  scanId: SCAN_ID,
  timeoutSeconds: 19_800,
  ...i,
});

interface Run {
  calls: CliCall[];
  /** The outputs as they stood when each command started. */
  outputsAtCall: Record<string, string>[];
  outputs: Map<string, string>;
  summaries: string[];
  infos: string[];
  warnings: string[];
  /** The messages the step failed with. */
  failed: string[];
  result?: GateReport | NewScan | ScanStatus;
  error?: Error;
}

/** Runs the mode of `inputs` against a CLI that answers each command with its reply. */
async function run(
  inputs: Inputs,
  replies: { new?: Reply; gate?: Reply; status?: Reply } = {},
): Promise<Run> {
  let clock = 0;
  const r: Run = {
    calls: [],
    outputsAtCall: [],
    outputs: new Map(),
    summaries: [],
    infos: [],
    warnings: [],
    failed: [],
  };
  const cli: CliRunner = async (call) => {
    r.calls.push(call);
    r.outputsAtCall.push(Object.fromEntries(r.outputs));
    const reply =
      call.args[1] === 'new'
        ? (replies.new ?? done(NEW_SCAN))
        : call.args[1] === 'status'
          ? (replies.status ?? done(scanStatus('in-progress', false)))
          : (replies.gate ?? done(report()));
    clock += reply.takesMs ?? 0;
    return { code: reply.code, stdout: reply.stdout ?? JSON.stringify(reply.json) };
  };
  const deps: Deps = {
    cli,
    log: { info: (m) => r.infos.push(m), warning: (m) => r.warnings.push(m) },
    setOutput: (name, value) => r.outputs.set(name, value),
    writeSummary: async (md) => void r.summaries.push(md),
    outDir: OUT_DIR,
    now: () => clock,
    setFailed: (message) => r.failed.push(message),
  };
  try {
    r.result = await runMode(inputs, deps);
  } catch (err) {
    r.error = err as Error;
  }
  return r;
}

const commands = (r: Run) => r.calls.map((c) => c.args.slice(0, 2).join(' '));
const gateResult = (r: Run) => r.result as GateReport | undefined;

const GATE_ARGS = ['scan', 'gate', '--scan', SCAN_ID, '--fail-on', 'critical', '--timeout', '19800s'];

describe('gate: true', () => {
  describe('an upload that passes', () => {
    let r: Run;
    before(async () => {
      r = await run(gate());
    });

    it('runs scan new, then scan gate', () => {
      assert.deepEqual(commands(r), ['scan new', 'scan gate']);
    });

    it('does not fail the step', () => {
      assert.deepEqual(r.failed, []);
    });

    it('uploads the image and the build VEX to the object with the key', () => {
      assert.deepEqual(r.calls[0].args, [
        'scan',
        'new',
        '--object-key',
        'gateway-firmware',
        '--object-name',
        'Gateway firmware',
        '--file',
        path.resolve('build/image.tar'),
        '--type',
        'linux',
        '--vex',
        path.resolve('build/image.vex.json'),
        '--format',
        'json',
      ]);
    });

    it('passes the API key and URL by environment', () => {
      assert.deepEqual(r.calls[0].env, {
        ANALYZER_API_KEY: 'test-key',
        ANALYZER_URL: 'https://analyzer.example.com/api',
      });
    });

    it('keeps the API key out of the arguments', () => {
      assert.ok(!r.calls.some((c) => c.args.includes('test-key')));
    });

    it('outputs the scan before it gates', () => {
      assert.deepEqual(r.outputsAtCall[1], {
        'scan-id': SCAN_ID,
        'object-id': OBJECT_ID,
        'scan-url': SCAN_URL,
      });
    });

    it('gates the scan at fail-on, in whole seconds, into the working directory', () => {
      assert.deepEqual(r.calls[1].args, [...GATE_ARGS, '--out-dir', OUT_DIR, '--format', 'json']);
    });

    it('passes the same environment to the gate', () => {
      assert.deepEqual(r.calls[1].env, r.calls[0].env);
    });

    it('passes', () => {
      assert.equal(gateResult(r)?.passed, true);
    });

    it('outputs the scan status', () => {
      assert.equal(r.outputs.get('scan-status'), 'success');
    });

    it('outputs the counts as JSON', () => {
      assert.deepEqual(JSON.parse(r.outputs.get('cve-counts') ?? ''), ONE_HIGH);
    });

    it('outputs the blocking count', () => {
      assert.equal(r.outputs.get('blocking'), '0');
    });

    it('outputs the paths of the evidence', () => {
      assert.deepEqual(
        [r.outputs.get('sbom-path'), r.outputs.get('vex-path'), r.outputs.get('report-path')],
        Object.values(EVIDENCE),
      );
    });

    it('writes the summary', () => {
      assert.deepEqual(r.summaries, [renderSummary(report())]);
    });

    it('leaves the scan link in the log to the CLI', () => {
      assert.deepEqual(r.infos, []);
    });
  });

  describe('an upload to an object by its id', () => {
    let r: Run;
    before(async () => {
      r = await run(gate({ target: BY_ID }));
    });

    it('names the object by its id, with no VEX', () => {
      assert.deepEqual(r.calls[0].args, [
        'scan',
        'new',
        '--object',
        OBJECT_ID,
        '--file',
        path.resolve('image.tar'),
        '--type',
        'docker',
        '--format',
        'json',
      ]);
    });
  });

  describe('an api-url in the /api/v2 form', () => {
    let r: Run;
    before(async () => {
      r = await run(gate({ apiUrl: 'https://analyzer.example.com/api/v2' }));
    });

    it('passes it as it is', () => {
      assert.equal(r.calls[0].env.ANALYZER_URL, 'https://analyzer.example.com/api/v2');
    });
  });

  describe('exit 1: blocking CVEs', () => {
    const failure = '1 CVE is reachable or unresolved at fail-on high or above';
    let r: Run;
    before(async () => {
      r = await run(gate({ failOn: 'high' }), {
        gate: gateFailed(report({ 'fail-on': 'high', passed: false, blocking: 1, failures: [failure] })),
      });
    });

    it('asks the CLI for the fail-on of the input', () => {
      assert.equal(r.calls[1].args[r.calls[1].args.indexOf('--fail-on') + 1], 'high');
    });

    it('does not pass', () => {
      assert.equal(gateResult(r)?.passed, false);
    });

    it('returns the failures', () => {
      assert.deepEqual(gateResult(r)?.failures, [failure]);
    });

    it('fails the step with the failures', () => {
      assert.deepEqual(r.failed, [failure]);
    });

    it('outputs the blocking count', () => {
      assert.equal(r.outputs.get('blocking'), '1');
    });

    it('keeps the evidence of a failed gate', () => {
      assert.equal(r.outputs.get('vex-path'), EVIDENCE['vex-path']);
    });

    it('lists the failures in the summary', () => {
      assert.ok(r.summaries[0].includes(`\n- ${failure}\n`));
    });
  });

  describe('exit 1: a scan that ended in error', () => {
    let r: Run;
    before(async () => {
      r = await run(gate(), {
        gate: gateFailed(report({ status: 'error', passed: false, failures: ['the scan failed'] })),
      });
    });

    it('outputs the scan status', () => {
      assert.equal(r.outputs.get('scan-status'), 'error');
    });
  });

  describe('exit 1 with a report that says passed', () => {
    let r: Run;
    before(async () => {
      r = await run(gate(), { gate: gateFailed(report({ passed: true })) });
    });

    it('does not pass: the exit code decides', () => {
      assert.equal(gateResult(r)?.passed, false);
    });

    it('fails the step, naming the scan when the report lists no failure', () => {
      assert.deepEqual(r.failed, [`The gate failed for scan ${SCAN_ID}`]);
    });
  });

  describe('exit 0 at fail-on none, with reachable critical CVEs', () => {
    const critical = counts({ critical: tiers({ all: 3, reachable: 1, unreachable: 1, unresolved: 1 }) });
    let r: Run;
    before(async () => {
      r = await run(gate({ failOn: 'none' }), {
        gate: done(report({ 'fail-on': 'none', blocking: 0, 'cve-counts': critical })),
      });
    });

    it('asks the CLI for fail-on none', () => {
      assert.equal(r.calls[1].args[r.calls[1].args.indexOf('--fail-on') + 1], 'none');
    });

    it('passes', () => {
      assert.equal(gateResult(r)?.passed, true);
    });

    it('does not fail the step', () => {
      assert.deepEqual(r.failed, []);
    });

    it('outputs no blocking CVEs', () => {
      assert.equal(r.outputs.get('blocking'), '0');
    });

    it('outputs the counts', () => {
      assert.deepEqual(JSON.parse(r.outputs.get('cve-counts') ?? ''), critical);
    });

    it('says it only reports in the summary', () => {
      assert.ok(r.summaries[0].includes("fail-on `none`: report only, CVEs don't fail the step."));
    });

    it('shows the counts per severity, none of them gated', () => {
      assert.ok(r.summaries[0].includes('| Critical | 3 | 1 | 1 | 1 | not gated |'));
    });
  });

  describe('exit 2 from scan gate, at the timeout', () => {
    // The CLI's own timeout error names the scan and how to gate it later.
    const error =
      `timed out after 5h30m waiting for the CVE classification of scan ${SCAN_ID} to settle. ` +
      `To gate the scan later, run: analyzer scan gate --scan ${SCAN_ID}`;
    let r: Run;
    before(async () => {
      r = await run(gate(), { gate: { ...noResult(error), takesMs: 19_800_000 } });
    });

    it('fails with the CLI error as it is, so it says how to gate the scan later once', () => {
      assert.equal(r.error?.message, error);
    });

    it('keeps the scan outputs', () => {
      assert.equal(r.outputs.get('scan-id'), SCAN_ID);
    });

    it('outputs no counts', () => {
      assert.equal(r.outputs.has('cve-counts'), false);
    });

    it('outputs no scan status, so a workflow tells no result from a failed gate', () => {
      assert.equal(r.outputs.has('scan-status'), false);
    });

    it('writes the error summary, with the link', () => {
      assert.deepEqual(r.summaries, [renderErrorSummary(error, SCAN_URL)]);
    });
  });

  describe('exit 2 from scan gate, on a refused key', () => {
    const error = 'the API key was refused (401)';
    let r: Run;
    before(async () => {
      r = await run(gate(), { gate: noResult(error) });
    });

    it('fails with the CLI error, and no hint to gate the scan later', () => {
      assert.equal(r.error?.message, error);
    });

    it('writes the error summary, with the link and no hint', () => {
      assert.deepEqual(r.summaries, [renderErrorSummary(error, SCAN_URL)]);
    });
  });

  describe('exit 2 from scan new', () => {
    const error = 'the API key was refused (401)';
    let r: Run;
    before(async () => {
      r = await run(gate(), { new: noResult(error) });
    });

    it('fails with the CLI error', () => {
      assert.equal(r.error?.message, error);
    });

    it('does not gate', () => {
      assert.deepEqual(commands(r), ['scan new']);
    });

    it('outputs nothing', () => {
      assert.equal(r.outputs.size, 0);
    });

    it('writes the error summary', () => {
      assert.deepEqual(r.summaries, [`## Exein Analyzer: error\n\n${error}\n`]);
    });
  });

  describe('a scan made earlier, by scan-id', () => {
    let r: Run;
    before(async () => {
      r = await run(gate({ target: { scanId: SCAN_ID }, timeoutSeconds: 1_800 }));
    });

    it('uploads nothing', () => {
      assert.deepEqual(commands(r), ['scan gate']);
    });

    it('outputs the scan id before it gates', () => {
      assert.deepEqual(r.outputsAtCall[0], { 'scan-id': SCAN_ID });
    });

    it('gates that scan, within the timeout', () => {
      assert.deepEqual(r.calls[0].args.slice(0, 8), [
        'scan',
        'gate',
        '--scan',
        SCAN_ID,
        '--fail-on',
        'critical',
        '--timeout',
        '1800s',
      ]);
    });

    it('outputs the object id of the scan', () => {
      assert.equal(r.outputs.get('object-id'), OBJECT_ID);
    });

    it('outputs the link of the scan', () => {
      assert.equal(r.outputs.get('scan-url'), SCAN_URL);
    });
  });

  describe('a scan made earlier that does not exist', () => {
    const error = `scan ${SCAN_ID} not found (404)`;
    let r: Run;
    before(async () => {
      r = await run(gate({ target: { scanId: SCAN_ID } }), { gate: noResult(error) });
    });

    it('fails with the CLI error, and no hint to gate the scan later', () => {
      assert.equal(r.error?.message, error);
    });

    it('writes the error summary, with no link and no hint', () => {
      assert.deepEqual(r.summaries, [renderErrorSummary(error)]);
    });
  });

  describe('the timeout', () => {
    it('stops an upload that runs past it', async () => {
      const r = await run(gate());
      assert.equal(r.calls[0].timeoutSeconds, 19_800);
    });

    it('counts the upload', async () => {
      const r = await run(gate(), { new: { ...done(NEW_SCAN), takesMs: 30 * 60_000 } });
      assert.equal(r.calls[1].args[r.calls[1].args.indexOf('--timeout') + 1], '18000s');
    });

    it('leaves the gate whole seconds', async () => {
      const r = await run(gate(), { new: { ...done(NEW_SCAN), takesMs: 1_500 } });
      assert.equal(r.calls[1].args[r.calls[1].args.indexOf('--timeout') + 1], '19798s');
    });

    describe('run out by the upload', () => {
      let r: Run;
      before(async () => {
        r = await run(gate(), { new: { ...done(NEW_SCAN), takesMs: 19_800_000 } });
      });

      it('fails, with how to gate the scan later', () => {
        assert.equal(
          r.error?.message,
          `The timeout of 5h30m ran out before scan ${SCAN_ID} finished. ` +
            `To gate this scan later, run the gate with scan-id: ${SCAN_ID}`,
        );
      });

      it('says it once in the summary, with the link', () => {
        assert.deepEqual(r.summaries, [renderErrorSummary(r.error?.message ?? '', SCAN_URL)]);
      });

      it('does not gate', () => {
        assert.deepEqual(commands(r), ['scan new']);
      });
    });
  });

  describe('a CLI outside the contract', () => {
    it('fails on stdout that is not JSON', async () => {
      const r = await run(gate(), { new: { code: 0, stdout: 'Scan created\n' } });
      assert.equal(r.error?.message, 'analyzer scan new exited 0 without its JSON output: Scan created');
    });

    it('fails on a scan new that prints no scan id', async () => {
      const r = await run(gate(), { new: done({ url: SCAN_URL }) });
      assert.equal(r.error?.message, `analyzer scan new printed no scan id: {"url":"${SCAN_URL}"}`);
    });

    it('fails on a scan new that exits 1, which only scan gate does', async () => {
      const r = await run(gate(), { new: { code: 1, stdout: '' } });
      assert.equal(r.error?.message, 'analyzer scan new exited 1');
    });

    it('fails on exit 2 with no error', async () => {
      const r = await run(gate(), { new: { code: 2, stdout: 'thread main panicked' } });
      assert.equal(r.error?.message, 'analyzer scan new exited 2: thread main panicked');
    });

    it('fails on an exit code outside the contract', async () => {
      const r = await run(gate(), { gate: { code: 101, stdout: '' } });
      assert.equal(r.error?.message, 'analyzer scan gate exited 101');
    });

    it('fails on a gate report with no decision', async () => {
      const r = await run(gate(), { gate: done({ 'scan-id': SCAN_ID }) });
      assert.match(r.error?.message ?? '', /^analyzer scan gate printed no decision: \{"scan-id":/);
    });
  });
});

describe('gate: false', () => {
  describe('an upload to an object by its key, with a build VEX', () => {
    let r: Run;
    before(async () => {
      r = await run(scan({ upload: BY_KEY }));
    });

    it('runs scan new only', () => {
      assert.deepEqual(commands(r), ['scan new']);
    });

    it('uploads the image with the build VEX', () => {
      assert.deepEqual(r.calls[0].args.slice(-4), [
        '--vex',
        path.resolve('build/image.vex.json'),
        '--format',
        'json',
      ]);
    });

    it('outputs the scan, its object and its link', () => {
      assert.deepEqual(Object.fromEntries(r.outputs), {
        'scan-id': SCAN_ID,
        'object-id': OBJECT_ID,
        'scan-url': SCAN_URL,
      });
    });

    it('leaves the scan link in the log to the CLI', () => {
      assert.deepEqual(r.infos, []);
    });

    it('writes the upload summary, with how to gate the scan later', () => {
      assert.deepEqual(r.summaries, [
        '## Exein Analyzer upload\n\n' +
          `Uploaded \`image.tar\` to object \`gateway-firmware\`: scan [${SCAN_ID}](${SCAN_URL}).\n\n` +
          `Gate it later with \`gate: 'true'\` and \`scan-id: ${SCAN_ID}\`.\n`,
      ]);
    });

    it('succeeds', () => {
      assert.equal(r.error, undefined);
    });
  });

  describe('an upload to an object by its id', () => {
    let r: Run;
    before(async () => {
      r = await run(scan());
    });

    it('names the object by its id', () => {
      assert.deepEqual(r.calls[0].args, [
        'scan',
        'new',
        '--object',
        OBJECT_ID,
        '--file',
        path.resolve('image.tar'),
        '--type',
        'docker',
        '--format',
        'json',
      ]);
    });

    it('names the object by its id in the summary', () => {
      assert.ok(r.summaries[0].includes(`to object \`${OBJECT_ID}\``));
    });
  });

  describe('exit 2 from scan new', () => {
    const error = 'the build VEX build/image.vex.json is not a JSON object';
    let r: Run;
    before(async () => {
      r = await run(scan({ upload: BY_KEY }), { new: noResult(error) });
    });

    it('fails with the CLI error', () => {
      assert.equal(r.error?.message, error);
    });

    it('outputs nothing', () => {
      assert.equal(r.outputs.size, 0);
    });

    it('writes the error summary', () => {
      assert.deepEqual(r.summaries, [renderErrorSummary(error)]);
    });
  });
});

describe('gate: status', () => {
  describe('a scan that is running', () => {
    let r: Run;
    before(async () => {
      r = await run(status());
    });

    it('runs scan status only, for the scan', () => {
      assert.deepEqual(
        r.calls.map((c) => c.args),
        [['scan', 'status', '--scan', SCAN_ID, '--format', 'json']],
      );
    });

    it('passes the API key and URL by environment', () => {
      assert.deepEqual(r.calls[0].env, {
        ANALYZER_API_KEY: 'test-key',
        ANALYZER_URL: 'https://analyzer.example.com/api',
      });
    });

    it('stops the CLI after 20m at most, though the timeout is longer', () => {
      assert.equal(r.calls[0].timeoutSeconds, 1_200);
    });

    it('outputs the scan id before it runs the CLI', () => {
      assert.deepEqual(r.outputsAtCall[0], { 'scan-id': SCAN_ID });
    });

    it('outputs the scan, its status, and that it has not finished', () => {
      assert.deepEqual(Object.fromEntries(r.outputs), {
        'scan-id': SCAN_ID,
        'object-id': OBJECT_ID,
        'scan-status': 'in-progress',
        finished: 'false',
      });
    });

    it('logs the status', () => {
      assert.deepEqual(r.infos, [`Scan ${SCAN_ID}: status in-progress, not finished`]);
    });

    it('writes a one-line summary', () => {
      assert.deepEqual(r.summaries, [
        `Exein Analyzer scan \`${SCAN_ID}\`: status \`in-progress\`, not finished.\n`,
      ]);
    });

    it('succeeds', () => {
      assert.equal(r.error, undefined);
    });
  });

  describe('a scan that finished', () => {
    let r: Run;
    before(async () => {
      r = await run(status(), { status: done(scanStatus('success', true)) });
    });

    it('outputs its status', () => {
      assert.equal(r.outputs.get('scan-status'), 'success');
    });

    it('outputs that it finished', () => {
      assert.equal(r.outputs.get('finished'), 'true');
    });

    it('says it finished in the summary', () => {
      assert.deepEqual(r.summaries, [renderStatusSummary(scanStatus('success', true))]);
    });
  });

  describe('a scan that ended in error', () => {
    let r: Run;
    before(async () => {
      r = await run(status(), { status: done(scanStatus('error', true)) });
    });

    it('does not fail: the gate decides', () => {
      assert.equal(r.error, undefined);
      assert.deepEqual(r.failed, []);
    });

    it('outputs its status', () => {
      assert.equal(r.outputs.get('scan-status'), 'error');
    });

    it('outputs that it finished', () => {
      assert.equal(r.outputs.get('finished'), 'true');
    });
  });

  it('stops the CLI at a timeout shorter than 20m', async () => {
    const r = await run(status({ timeoutSeconds: 300 }));
    assert.equal(r.calls[0].timeoutSeconds, 300);
  });

  describe('exit 2', () => {
    const error = `scan ${SCAN_ID} not found (404)`;
    let r: Run;
    before(async () => {
      r = await run(status(), { status: noResult(error) });
    });

    it('fails with the CLI error', () => {
      assert.equal(r.error?.message, error);
    });

    it('outputs the scan id only', () => {
      assert.deepEqual(Object.fromEntries(r.outputs), { 'scan-id': SCAN_ID });
    });

    it('writes no summary', () => {
      assert.equal(r.summaries.length, 0);
    });
  });

  describe('a CLI outside the contract', () => {
    it('fails on a status with no finished', async () => {
      const r = await run(status(), { status: done({ id: SCAN_ID, status: 'success' }) });
      assert.equal(
        r.error?.message,
        `analyzer scan status printed no status: {"id":"${SCAN_ID}","status":"success"}`,
      );
    });

    it('fails on exit 1, which only scan gate does', async () => {
      const r = await run(status(), { status: { code: 1, stdout: '' } });
      assert.equal(r.error?.message, 'analyzer scan status exited 1');
    });
  });
});

describe('renderSummary', () => {
  it('says the gate passed, with the counts per severity', () => {
    assert.equal(
      renderSummary(report()),
      [
        '## Exein Analyzer release gate: passed',
        '',
        'No CVEs at fail-on `critical` or above are reachable or unresolved.',
        '',
        `Scan [${SCAN_ID}](${SCAN_URL}), status \`success\`. Classification \`settled\`, checked at 2026-11-05T10:00:00Z.`,
        '',
        '| Severity | All | Reachable | Unreachable | Unresolved | Blocking |',
        '|---|---:|---:|---:|---:|---:|',
        '| Critical | 0 | 0 | 0 | 0 | 0 |',
        '| High | 1 | 1 | 0 | 0 | not gated |',
        '| Medium | 0 | 0 | 0 | 0 | not gated |',
        '| Low | 0 | 0 | 0 | 0 | not gated |',
        '| Unknown | 0 | 0 | 0 | 0 | not gated |',
        '',
      ].join('\n'),
    );
  });

  it('marks the blocking counts at fail-on and above', () => {
    const md = renderSummary(
      report({ 'fail-on': 'high', passed: false, blocking: 1, failures: ['1 CVE blocks'] }),
    );
    assert.ok(md.includes('| High | 1 | 1 | 0 | 0 | **1** |'));
  });

  it('names the classification when it has not settled, and the catalog date', () => {
    const md = renderSummary(
      report({ 'cve-counts': counts({ settled: false, 'catalog-as-of': '2026-11-04T00:00:00Z' }) }),
    );
    assert.ok(
      md.includes(
        'Classification `settled`, not settled, checked at 2026-11-05T10:00:00Z, catalog as of 2026-11-04T00:00:00Z.',
      ),
    );
  });

  it('notes a scan with no reachability classification', () => {
    const md = renderSummary(report({ 'cve-counts': counts({ classification: 'not-applicable' }) }));
    assert.ok(
      md.includes('This scan has no reachability classification, so each of its CVEs counts as unresolved.'),
    );
  });

  describe('a canceled scan with no counts', () => {
    const md = renderSummary(
      report({
        status: 'canceled',
        passed: false,
        blocking: null,
        'cve-counts': null,
        'no-counts-reason': 'the scan has no CVE check',
        'vex-path': null,
        failures: [
          `Scan ${SCAN_ID} ended with status canceled`,
          `The VEX of scan ${SCAN_ID} is missing: 404`,
        ],
      }),
    );

    it('says the gate failed', () => {
      assert.ok(md.startsWith('## Exein Analyzer release gate: failed\n'));
    });

    it('lists why', () => {
      assert.ok(
        md.includes(
          `\n- Scan ${SCAN_ID} ended with status canceled\n- The VEX of scan ${SCAN_ID} is missing: 404\n`,
        ),
      );
    });

    it('says why it has no counts', () => {
      assert.ok(md.includes('The scan has no CVE counts: the scan has no CVE check'));
    });

    it('shows no table', () => {
      assert.ok(!md.includes('| Severity |'));
    });
  });

  it('says why the report is missing', () => {
    const md = renderSummary(
      report({
        'report-path': null,
        warnings: [`The PDF report of scan ${SCAN_ID} is missing: the scan has no score`],
      }),
    );
    assert.ok(
      md.endsWith(
        `\nThe PDF report of scan ${SCAN_ID} is missing: the scan has no score. The gate does not need it.\n`,
      ),
    );
  });
});
