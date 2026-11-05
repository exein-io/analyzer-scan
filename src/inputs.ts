/** The image types the Analyzer CLI scans. */
export const SCAN_TYPES = ['docker', 'linux'] as const;

export type ScanType = (typeof SCAN_TYPES)[number];

export const FAIL_ON_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

/** A severity that `fail-on` can name as the lowest that blocks. */
export type Severity = (typeof FAIL_ON_SEVERITIES)[number];

/** The values of `fail-on`: the lowest severity that blocks, or `none`, which only reports. */
export const FAIL_ON_VALUES = [...FAIL_ON_SEVERITIES, 'none'] as const;

export type FailOn = (typeof FAIL_ON_VALUES)[number];

/** The Analyzer CLI release this major of the action is built for. */
export const DEFAULT_CLI_VERSION = 'v1.0.0';

/** What the `gate` input asks for: a scan, the release gate, or a scan's status. */
export type Mode = 'scan' | 'gate' | 'status';

export function parseMode(value: string): Mode {
  switch (value.trim().toLowerCase()) {
    case '':
    case 'false':
      return 'scan';
    case 'true':
      return 'gate';
    case 'status':
      return 'status';
    default:
      throw new Error(`Invalid gate "${value}". Must be true, false or status`);
  }
}

/** Inputs v2 removed. A workflow that still sets one to true gets the way to the same result. */
const REMOVED_DOWNLOAD_INPUTS = ['download-report', 'download-sbom'] as const;

export const REMOVED_DOWNLOADS_MESSAGE =
  "download-report and download-sbom were removed in v2: use gate: 'true' with fail-on: none, " +
  'which waits for the scan and downloads the SBOM, VEX and report without failing on CVEs';

/** The object to upload to: one that exists, by its id, or the one with a key, made when the key is new. */
export type ObjectRef = { id: string } | { key: string; name?: string };

/** An image to upload, which starts a scan. */
export interface Upload {
  object: ObjectRef;
  scanType: ScanType;
  filePath: string;
  /** The build's VEX, sent before the image. */
  buildVex?: string;
}

interface Common {
  apiKey: string;
  apiUrl: string;
  cliVersion: string;
}

/** `gate: false`: upload an image, which starts a scan, for a later gate by its scan id. */
export interface ScanInputs extends Common {
  mode: 'scan';
  upload: Upload;
}

/** `gate: true`: upload an image, or take a scan made earlier, and gate it. */
export interface GateInputs extends Common {
  mode: 'gate';
  failOn: FailOn;
  target: Upload | { scanId: string };
  /** How long the step waits for the scan, counted from its start. */
  timeoutSeconds: number;
}

/** `gate: status`: read the status of a scan made earlier. */
export interface StatusInputs extends Common {
  mode: 'status';
  scanId: string;
  timeoutSeconds: number;
}

export type Inputs = ScanInputs | GateInputs | StatusInputs;

/** The inputs of an upload, which `gate: status` refuses. */
const UPLOAD_INPUTS = ['object-id', 'object-key', 'object-name', 'file-path', 'build-vex'] as const;

/** Reads an action input, as `core.getInput` does. */
export type GetInput = (name: string, options?: { required?: boolean }) => string;

/** `5h30m`, `90m`, `45s`: hours, minutes and seconds, in that order, each optional. In seconds. */
export function parseDuration(value: string): number {
  const match = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(value.trim());
  const seconds = match
    ? Number(match[1] ?? 0) * 3600 + Number(match[2] ?? 0) * 60 + Number(match[3] ?? 0)
    : 0;
  if (seconds <= 0) {
    throw new Error(`Invalid timeout "${value}". Use hours, minutes and seconds, such as 5h30m, 90m or 45s`);
  }
  return seconds;
}

/** `19800` as `5h30m`. */
export function formatSeconds(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${h ? `${h}h` : ''}${m ? `${m}m` : ''}${s || (!h && !m) ? `${s}s` : ''}`;
}

function parseObject(getInput: GetInput, mode: Mode): ObjectRef {
  const id = getInput('object-id');
  const key = getInput('object-key');
  const name = getInput('object-name');
  if (id && key) {
    throw new Error('Set object-id or object-key, not both');
  }
  if (id) {
    if (name) {
      throw new Error('object-name names the object that object-key makes, so it goes with object-key');
    }
    return { id };
  }
  if (key) {
    return name ? { key, name } : { key };
  }
  throw new Error(
    mode === 'gate'
      ? 'The gate needs object-id or object-key, to upload an image, or scan-id, to gate a scan made earlier'
      : 'Set object-id or object-key: the object to upload the image to',
  );
}

function parseUpload(getInput: GetInput, mode: Mode): Upload {
  const object = parseObject(getInput, mode);
  const scanType = getInput('scan-type', { required: true });
  if (!SCAN_TYPES.includes(scanType as ScanType)) {
    const v1 = scanType === 'idf' || scanType === 'sbom' ? `. ${scanType} scans need analyzer-scan v1` : '';
    throw new Error(`Invalid scan-type "${scanType}". Must be one of: ${SCAN_TYPES.join(', ')}${v1}`);
  }
  const buildVex = getInput('build-vex');
  return {
    object,
    scanType: scanType as ScanType,
    filePath: getInput('file-path', { required: true }),
    ...(buildVex ? { buildVex } : {}),
  };
}

function parseFailOn(value: string): FailOn {
  const failOn = (value || 'critical').toLowerCase();
  if (!FAIL_ON_VALUES.includes(failOn as FailOn)) {
    throw new Error(`Invalid fail-on "${failOn}". Must be one of: ${FAIL_ON_VALUES.join(', ')}`);
  }
  return failOn as FailOn;
}

export function parseInputs(getInput: GetInput): Inputs {
  if (REMOVED_DOWNLOAD_INPUTS.some((name) => getInput(name).trim().toLowerCase() === 'true')) {
    throw new Error(REMOVED_DOWNLOADS_MESSAGE);
  }
  const mode = parseMode(getInput('gate'));
  const common: Common = {
    apiKey: getInput('api-key', { required: true }),
    apiUrl: getInput('api-url', { required: true }),
    cliVersion: getInput('cli-version') || DEFAULT_CLI_VERSION,
  };
  const scanId = getInput('scan-id');
  // gate: false does not wait, so it does not read the timeout.
  const timeoutSeconds = () => parseDuration(getInput('timeout') || '5h30m');

  if (mode === 'status') {
    if (!scanId) {
      throw new Error('gate: status needs scan-id, the scan to check');
    }
    const set = UPLOAD_INPUTS.filter((name) => getInput(name));
    if (set.length > 0) {
      throw new Error(`gate: status uploads nothing, so it does not take ${set.join(', ')}`);
    }
    return { ...common, mode, scanId, timeoutSeconds: timeoutSeconds() };
  }

  if (mode === 'gate') {
    const gate = {
      ...common,
      mode,
      failOn: parseFailOn(getInput('fail-on')),
      timeoutSeconds: timeoutSeconds(),
    };
    if (!scanId) {
      return { ...gate, target: parseUpload(getInput, mode) };
    }
    if (getInput('object-id') || getInput('object-key') || getInput('object-name')) {
      throw new Error(
        'Set object-id or object-key (with object-name) to upload an image, or scan-id to gate a scan made earlier, not both',
      );
    }
    if (getInput('build-vex')) {
      throw new Error('build-vex goes with the upload of an image, not with scan-id');
    }
    return { ...gate, target: { scanId } };
  }

  if (scanId) {
    throw new Error(
      'scan-id names a scan made earlier, for gate: true or status, so it does not go with gate: false',
    );
  }
  return { ...common, mode, upload: parseUpload(getInput, mode) };
}
