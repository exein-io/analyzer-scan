import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { after, before, describe, it } from 'node:test';
import { spawnCli, type CliEnv, type CliExit, type GateReport } from './analyzer.js';
import { runGate, type Deps } from './gate.js';
import type { FailOn, GateInputs } from './inputs.js';

const ENV: CliEnv = { ANALYZER_API_KEY: 'test-key', ANALYZER_URL: 'https://analyzer.example.com/api' };

/**
 * A fake `analyzer`, run as a real process. `scan gate` logs a progress line, then waits until the action has
 * logged it, so a runner that reads stderr only at the exit fails here.
 */
const FAKE_ANALYZER = `#!${process.execPath}
const fs = require('fs');
const path = require('path');
const args = process.argv.slice(2);
const opt = (name) => args[args.indexOf(name) + 1];
const print = (code, doc) => {
  console.log(JSON.stringify(doc));
  process.exitCode = code;
};
const url = 'https://analyzer.example.com/objects/object-1/scans/scan-1';
const tiers = (reachable) => ({ all: reachable, reachable, unreachable: 0, unresolved: 0 });

function gate() {
  const failOn = opt('--fail-on');
  const passed = failOn !== 'high';
  const file = (name, body) => {
    const p = path.join(opt('--out-dir'), opt('--scan') + '-' + name);
    fs.writeFileSync(p, body);
    return p;
  };
  console.error('Scan status: success');
  print(passed ? 0 : 1, {
    'scan-id': opt('--scan'), 'object-id': 'object-1', url, status: 'success', 'fail-on': failOn, passed,
    blocking: passed ? 0 : 1,
    'cve-counts': {
      classification: 'settled', settled: true, 'checked-at': '2026-11-05T10:00:00Z',
      critical: tiers(0), high: tiers(1), medium: tiers(0), low: tiers(0), unknown: tiers(0),
    },
    'no-counts-reason': null,
    'sbom-path': file('sbom.json', '{}'), 'vex-path': file('vex.json', '{}'), 'report-path': file('report.pdf', '%PDF'),
    failures: passed ? [] : ['1 CVE is reachable or unresolved at fail-on high or above'],
    warnings: [],
  });
}

switch (args.slice(0, 2).join(' ')) {
  case 'scan new':
    console.error('Uploading ' + path.basename(opt('--file')));
    print(0, { id: 'scan-1', 'object-id': 'object-1', url });
    break;
  case 'scan gate': {
    console.error('Scan status: in-progress');
    const marker = path.join(__dirname, 'streamed');
    const until = Date.now() + 10000;
    const poll = () => {
      if (fs.existsSync(marker)) gate();
      else if (Date.now() > until) print(2, { error: 'the action did not log the progress while the CLI ran' });
      else setTimeout(poll, 20);
    };
    poll();
    break;
  }
  case 'env x':
    print(0, { args, key: process.env.ANALYZER_API_KEY, url: process.env.ANALYZER_URL, path: !!process.env.PATH });
    break;
  case 'no newline':
    process.stderr.write('a last line with no newline');
    print(0, {});
    break;
  case 'stop self':
    process.kill(process.pid, 'SIGTERM');
    break;
  case 'hang forever':
    setInterval(() => {}, 1000);
    break;
  default:
    print(2, { error: 'unknown command: ' + args.join(' ') });
}
`;

let dir: string;
let analyzer: string;

before(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analyzer-scan-test-'));
  analyzer = path.join(dir, 'analyzer');
  fs.writeFileSync(analyzer, FAKE_ANALYZER, { mode: 0o755 });
});

after(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

/** Runs the fake CLI once, and returns its exit and the stderr lines it logged. */
async function spawn(args: string[], timeoutSeconds?: number): Promise<{ exit: CliExit; lines: string[] }> {
  const lines: string[] = [];
  const exit = await spawnCli(analyzer, (line) => lines.push(line))({ args, env: ENV, timeoutSeconds });
  return { exit, lines };
}

describe('spawnCli', () => {
  describe('a command', () => {
    let doc: { args: string[]; key: string; url: string; path: boolean };
    before(async () => {
      doc = JSON.parse((await spawn(['env', 'x', 'a b', '--flag'])).exit.stdout);
    });

    it('passes the args as they are', () => {
      assert.deepEqual(doc.args, ['env', 'x', 'a b', '--flag']);
    });

    it('passes the API key by environment', () => {
      assert.equal(doc.key, 'test-key');
    });

    it('passes the API URL by environment', () => {
      assert.equal(doc.url, 'https://analyzer.example.com/api');
    });

    it('keeps the rest of the environment', () => {
      assert.equal(doc.path, true);
    });
  });

  describe('a command with no result', () => {
    let exit: CliExit;
    before(async () => {
      ({ exit } = await spawn(['scan', 'list']));
    });

    it('returns its exit code', () => {
      assert.equal(exit.code, 2);
    });

    it('returns its stdout', () => {
      assert.deepEqual(JSON.parse(exit.stdout), { error: 'unknown command: scan list' });
    });
  });

  it('logs a last stderr line with no newline', async () => {
    assert.deepEqual((await spawn(['no', 'newline'])).lines, ['a last line with no newline']);
  });

  it('rejects when the CLI is missing', async () => {
    const missing = path.join(dir, 'missing');
    await assert.rejects(
      spawnCli(missing, () => {})({ args: [], env: ENV }),
      new RegExp(`^Error: Could not run the Analyzer CLI at ${missing}: spawn ${missing} ENOENT$`),
    );
  });

  it('rejects when a signal stops the CLI', async () => {
    await assert.rejects(spawn(['stop', 'self']), /^Error: The Analyzer CLI was stopped by SIGTERM$/);
  });

  describe('a time limit', () => {
    it('stops a CLI that runs past it', async () => {
      await assert.rejects(
        spawn(['hang', 'forever'], 0.2),
        /^Error: The Analyzer CLI did not exit within 0.2s, so the action stopped it$/,
      );
    });

    it('returns a command that exits within it', async () => {
      assert.equal((await spawn(['env', 'x'], 60)).exit.code, 0);
    });
  });
});

describe('the gate, through a real process', () => {
  interface Run {
    lines: string[];
    outputs: Map<string, string>;
    report: GateReport;
  }

  async function gate(failOn: FailOn): Promise<Run> {
    const outDir = fs.mkdtempSync(path.join(dir, 'out-'));
    const marker = path.join(dir, 'streamed');
    fs.rmSync(marker, { force: true });
    const r = { lines: [] as string[], outputs: new Map<string, string>() };
    const log = (line: string) => {
      r.lines.push(line);
      if (line === 'Scan status: in-progress') {
        fs.writeFileSync(marker, '');
      }
    };
    const deps: Deps = {
      cli: spawnCli(analyzer, log),
      log: { info: () => {}, warning: () => {} },
      setOutput: (name, value) => r.outputs.set(name, value),
      writeSummary: async () => {},
      outDir,
      now: Date.now,
      setFailed: () => {},
    };
    const inputs: GateInputs = {
      apiKey: ENV.ANALYZER_API_KEY,
      apiUrl: ENV.ANALYZER_URL,
      cliVersion: 'v1.0.0',
      timeoutSeconds: 60,
      mode: 'gate',
      failOn,
      target: { object: { key: 'gateway-firmware' }, scanType: 'linux', filePath: 'image.tar' },
    };
    return { ...r, report: await runGate(inputs, deps) };
  }

  describe('a pass', () => {
    let r: Run;
    before(async () => {
      r = await gate('critical');
    });

    it('logs the progress of the CLI while it runs', () => {
      assert.deepEqual(r.lines, ['Uploading image.tar', 'Scan status: in-progress', 'Scan status: success']);
    });

    it('passes', () => {
      assert.equal(r.report.passed, true);
    });

    it('outputs the scan id of scan new', () => {
      assert.equal(r.outputs.get('scan-id'), 'scan-1');
    });

    it('outputs the counts of scan gate', () => {
      assert.equal(JSON.parse(r.outputs.get('cve-counts') ?? '').high.reachable, 1);
    });

    it('outputs the SBOM the CLI wrote', () => {
      assert.equal(fs.readFileSync(r.outputs.get('sbom-path') ?? '', 'utf8'), '{}');
    });
  });

  describe('a fail', () => {
    let r: Run;
    before(async () => {
      r = await gate('high');
    });

    it('does not pass', () => {
      assert.equal(r.report.passed, false);
    });

    it('returns the failures', () => {
      assert.deepEqual(r.report.failures, ['1 CVE is reachable or unresolved at fail-on high or above']);
    });

    it('outputs the blocking count', () => {
      assert.equal(r.outputs.get('blocking'), '1');
    });
  });
});
