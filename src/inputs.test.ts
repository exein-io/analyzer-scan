import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { formatSeconds, parseDuration, parseInputs, parseMode, type GetInput } from './inputs.js';

/** Reads inputs from a record, failing on a missing required one as `core.getInput` does. */
function inputs(values: Record<string, string>): GetInput {
  return (name, options) => {
    const value = values[name] ?? '';
    if (options?.required && !value) {
      throw new Error(`Input required and not supplied: ${name}`);
    }
    return value;
  };
}

const CONNECTION = { 'api-key': 'k', 'api-url': 'https://analyzer.example.com/api' };
const SCAN = { ...CONNECTION, 'object-id': 'o', 'scan-type': 'linux', 'file-path': 'image.tar' };
const GATE = {
  ...CONNECTION,
  gate: 'true',
  'object-key': 'gateway',
  'scan-type': 'linux',
  'file-path': 'image.tar',
};
const STATUS = { ...CONNECTION, gate: 'status', 'scan-id': 's' };

describe('parseDuration', () => {
  it('reads hours and minutes, in seconds', () => {
    assert.equal(parseDuration('5h30m'), 19_800);
  });

  it('reads minutes', () => {
    assert.equal(parseDuration('90m'), 5_400);
  });

  it('reads seconds', () => {
    assert.equal(parseDuration('45s'), 45);
  });

  it('refuses a number without a unit', () => {
    assert.throws(() => parseDuration('90'), /Invalid timeout "90"/);
  });

  it('refuses zero', () => {
    assert.throws(() => parseDuration('0m'), /Invalid timeout/);
  });
});

describe('formatSeconds', () => {
  it('writes hours and minutes', () => {
    assert.equal(formatSeconds(19_800), '5h30m');
  });

  it('writes minutes and seconds', () => {
    assert.equal(formatSeconds(90), '1m30s');
  });

  it('writes whole hours', () => {
    assert.equal(formatSeconds(3_600), '1h');
  });
});

describe('parseMode', () => {
  it('scans by default', () => {
    assert.equal(parseMode(''), 'scan');
  });

  it('scans with false', () => {
    assert.equal(parseMode('false'), 'scan');
  });

  it('gates with true', () => {
    assert.equal(parseMode('true'), 'gate');
  });

  it('reads a status with status', () => {
    assert.equal(parseMode('status'), 'status');
  });

  it('refuses anything else', () => {
    assert.throws(() => parseMode('yes'), /^Error: Invalid gate "yes". Must be true, false or status$/);
  });

  it('refuses upload, which v2 dropped for false', () => {
    assert.throws(() => parseMode('upload'), /^Error: Invalid gate "upload". Must be true, false or status$/);
  });
});

describe('parseInputs', () => {
  describe('every mode', () => {
    it('defaults the CLI to the release this action is built for', () => {
      assert.equal(parseInputs(inputs(SCAN)).cliVersion, 'v1.0.0');
    });

    it('takes a pinned CLI', () => {
      assert.equal(parseInputs(inputs({ ...SCAN, 'cli-version': 'v1.2.0' })).cliVersion, 'v1.2.0');
    });

    it('defaults the timeout of the gate to 5h30m', () => {
      const parsed = parseInputs(inputs(GATE));
      assert.equal(parsed.mode === 'gate' && parsed.timeoutSeconds, 19_800);
    });

    it('needs the API key', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'api-key': '' })),
        /Input required and not supplied: api-key/,
      );
    });
  });

  describe('scan types', () => {
    it('take docker', () => {
      const parsed = parseInputs(inputs({ ...SCAN, 'scan-type': 'docker' }));
      assert.equal(parsed.mode === 'scan' && parsed.upload.scanType, 'docker');
    });

    it('refuse idf, which needs v1', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'scan-type': 'idf' })),
        /^Error: Invalid scan-type "idf". Must be one of: docker, linux. idf scans need analyzer-scan v1$/,
      );
    });

    it('refuse sbom, which needs v1', () => {
      assert.throws(
        () => parseInputs(inputs({ ...GATE, 'scan-type': 'sbom' })),
        /sbom scans need analyzer-scan v1$/,
      );
    });

    it('refuse anything else', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'scan-type': 'rtos' })),
        /^Error: Invalid scan-type "rtos". Must be one of: docker, linux$/,
      );
    });
  });

  describe('gate: false', () => {
    it('reads the upload to an object by its id', () => {
      assert.deepEqual(parseInputs(inputs({ ...SCAN, 'build-vex': 'build.vex.json' })), {
        apiKey: 'k',
        apiUrl: 'https://analyzer.example.com/api',
        cliVersion: 'v1.0.0',
        mode: 'scan',
        upload: { object: { id: 'o' }, scanType: 'linux', filePath: 'image.tar', buildVex: 'build.vex.json' },
      });
    });

    it('takes an object key instead, with a name', () => {
      const parsed = parseInputs(
        inputs({ ...SCAN, 'object-id': '', 'object-key': 'gateway', 'object-name': 'Gateway' }),
      );
      assert.deepEqual(parsed.mode === 'scan' && parsed.upload.object, { key: 'gateway', name: 'Gateway' });
    });

    it('does not read the timeout, since it does not wait', () => {
      assert.equal(parseInputs(inputs({ ...SCAN, timeout: 'soon' })).mode, 'scan');
    });

    it('does not read fail-on', () => {
      assert.equal(parseInputs(inputs({ ...SCAN, 'fail-on': 'off' })).mode, 'scan');
    });

    it('needs an object', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'object-id': '' })),
        /^Error: Set object-id or object-key: the object to upload the image to$/,
      );
    });

    it('refuses both object-id and object-key', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'object-key': 'gateway' })),
        /Set object-id or object-key, not both/,
      );
    });

    it('refuses an object name with object-id', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'object-name': 'Gateway' })),
        /object-name names the object that object-key makes/,
      );
    });

    it('needs a file', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'file-path': '' })),
        /Input required and not supplied: file-path/,
      );
    });

    it('refuses scan-id', () => {
      assert.throws(
        () => parseInputs(inputs({ ...SCAN, 'scan-id': 's' })),
        /scan-id names a scan made earlier, for gate: true or status, so it does not go with gate: false/,
      );
    });
  });

  describe('gate: true', () => {
    it('reads the upload to an object by its key', () => {
      assert.deepEqual(parseInputs(inputs(GATE)), {
        apiKey: 'k',
        apiUrl: 'https://analyzer.example.com/api',
        cliVersion: 'v1.0.0',
        timeoutSeconds: 19_800,
        mode: 'gate',
        failOn: 'critical',
        target: { object: { key: 'gateway' }, scanType: 'linux', filePath: 'image.tar' },
      });
    });

    it('takes an object id instead', () => {
      const parsed = parseInputs(inputs({ ...GATE, 'object-key': '', 'object-id': 'o' }));
      assert.deepEqual(parsed.mode === 'gate' && 'object' in parsed.target && parsed.target.object, {
        id: 'o',
      });
    });

    it('reads the timeout', () => {
      const parsed = parseInputs(inputs({ ...GATE, timeout: '90m' }));
      assert.equal(parsed.mode === 'gate' && parsed.timeoutSeconds, 5_400);
    });

    it('reads fail-on in any case', () => {
      const parsed = parseInputs(inputs({ ...GATE, 'fail-on': 'HIGH' }));
      assert.equal(parsed.mode === 'gate' && parsed.failOn, 'high');
    });

    it('reads fail-on none, which only reports', () => {
      const parsed = parseInputs(inputs({ ...GATE, 'fail-on': 'none' }));
      assert.equal(parsed.mode === 'gate' && parsed.failOn, 'none');
    });

    it('names none among the values of fail-on', () => {
      assert.throws(
        () => parseInputs(inputs({ ...GATE, 'fail-on': 'off' })),
        /Invalid fail-on "off". Must be one of: critical, high, medium, low, none$/,
      );
    });

    it('gates a scan made earlier by its id', () => {
      const parsed = parseInputs(inputs({ ...CONNECTION, gate: 'true', 'scan-id': 's' }));
      assert.deepEqual(parsed.mode === 'gate' && parsed.target, { scanId: 's' });
    });

    it('refuses both object-key and scan-id', () => {
      assert.throws(() => parseInputs(inputs({ ...GATE, 'scan-id': 's' })), /not both/);
    });

    it('refuses both object-id and scan-id', () => {
      assert.throws(
        () => parseInputs(inputs({ ...CONNECTION, gate: 'true', 'object-id': 'o', 'scan-id': 's' })),
        /not both/,
      );
    });

    it('refuses neither an object nor scan-id', () => {
      assert.throws(
        () => parseInputs(inputs({ ...CONNECTION, gate: 'true' })),
        /The gate needs object-id or object-key, to upload an image, or scan-id/,
      );
    });

    it('reads the build VEX of the upload', () => {
      const parsed = parseInputs(inputs({ ...GATE, 'build-vex': 'build.vex.json' }));
      assert.equal(
        parsed.mode === 'gate' && 'object' in parsed.target && parsed.target.buildVex,
        'build.vex.json',
      );
    });

    it('refuses an object name with scan-id', () => {
      assert.throws(
        () => parseInputs(inputs({ ...CONNECTION, gate: 'true', 'scan-id': 's', 'object-name': 'Gateway' })),
        /not both/,
      );
    });

    it('refuses a build VEX with scan-id, which has nothing to upload', () => {
      assert.throws(
        () =>
          parseInputs(inputs({ ...CONNECTION, gate: 'true', 'scan-id': 's', 'build-vex': 'build.vex.json' })),
        /build-vex goes with the upload of an image, not with scan-id/,
      );
    });

    it('refuses a file path with scan-id, which has nothing to upload', () => {
      assert.throws(
        () => parseInputs(inputs({ ...CONNECTION, gate: 'true', 'scan-id': 's', 'file-path': 'image.tar' })),
        /file-path goes with the upload of an image, not with scan-id/,
      );
    });

    it('refuses a scan type with scan-id, which has nothing to upload', () => {
      assert.throws(
        () => parseInputs(inputs({ ...CONNECTION, gate: 'true', 'scan-id': 's', 'scan-type': 'linux' })),
        /scan-type goes with the upload of an image, not with scan-id/,
      );
    });
  });

  describe('gate: upload, which v2 dropped', () => {
    it('is refused, with the values gate takes', () => {
      assert.throws(
        () => parseInputs(inputs({ ...GATE, gate: 'upload' })),
        /^Error: Invalid gate "upload". Must be true, false or status$/,
      );
    });
  });

  describe('download-report and download-sbom, which v2 removed', () => {
    const removed =
      /^Error: download-report and download-sbom were removed in v2: use gate: 'true' with fail-on: none, which waits for the scan and downloads the SBOM, VEX and report without failing on CVEs$/;

    it('fail at once on download-report: true', () => {
      assert.throws(() => parseInputs(inputs({ ...SCAN, 'download-report': 'true' })), removed);
    });

    it('fail at once on download-sbom: true', () => {
      assert.throws(() => parseInputs(inputs({ ...SCAN, 'download-sbom': 'true' })), removed);
    });

    it('fail before any other input is read', () => {
      const read: string[] = [];
      try {
        parseInputs((name, options) => {
          read.push(name);
          return inputs({ 'download-sbom': 'true' })(name, options);
        });
      } catch {
        // The removed input; the test is what was read before it.
      }
      assert.deepEqual(read, ['download-report', 'download-sbom']);
    });

    it('fail with the gate too', () => {
      assert.throws(() => parseInputs(inputs({ ...GATE, 'download-report': 'TRUE' })), removed);
    });

    it('pass when false', () => {
      assert.equal(
        parseInputs(inputs({ ...SCAN, 'download-report': 'false', 'download-sbom': 'false' })).mode,
        'scan',
      );
    });
  });

  describe('gate: status', () => {
    it('reads the scan id, with no upload', () => {
      assert.deepEqual(parseInputs(inputs(STATUS)), {
        apiKey: 'k',
        apiUrl: 'https://analyzer.example.com/api',
        cliVersion: 'v1.0.0',
        timeoutSeconds: 19_800,
        mode: 'status',
        scanId: 's',
      });
    });

    it('reads the timeout', () => {
      const parsed = parseInputs(inputs({ ...STATUS, timeout: '5m' }));
      assert.equal(parsed.mode === 'status' && parsed.timeoutSeconds, 300);
    });

    it('needs scan-id', () => {
      assert.throws(
        () => parseInputs(inputs({ ...STATUS, 'scan-id': '' })),
        /^Error: gate: status needs scan-id, the scan to check$/,
      );
    });

    it('does not read scan-type', () => {
      assert.equal(parseInputs(inputs({ ...STATUS, 'scan-type': 'rtos' })).mode, 'status');
    });

    it('does not read fail-on', () => {
      assert.equal(parseInputs(inputs({ ...STATUS, 'fail-on': 'off' })).mode, 'status');
    });

    for (const name of ['object-id', 'object-key', 'object-name', 'file-path', 'build-vex']) {
      it(`refuses ${name}`, () => {
        assert.throws(
          () => parseInputs(inputs({ ...STATUS, [name]: 'x' })),
          new RegExp(`^Error: gate: status uploads nothing, so it does not take ${name}$`),
        );
      });
    }

    it('names every upload input it refuses', () => {
      assert.throws(
        () => parseInputs(inputs({ ...STATUS, 'object-key': 'gateway', 'file-path': 'image.tar' })),
        /does not take object-key, file-path$/,
      );
    });
  });
});
