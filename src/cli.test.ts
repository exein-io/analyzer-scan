import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { cliDownloadUrl } from './cli.js';

const RELEASE = 'releases/analyzer-cli/v1.0.0/analyzer-x86_64-unknown-linux-gnu.tar.gz';

describe('cliDownloadUrl', () => {
  it('downloads from the API root', () => {
    assert.equal(
      cliDownloadUrl('https://analyzer.example.com/api/', 'v1.0.0', 'x86_64-unknown-linux-gnu'),
      `https://analyzer.example.com/api/${RELEASE}`,
    );
  });

  it('downloads from the API root for an /api/v2 URL', () => {
    assert.equal(
      cliDownloadUrl('https://analyzer.example.com/api/v2', 'v1.0.0', 'x86_64-unknown-linux-gnu'),
      `https://analyzer.example.com/api/${RELEASE}`,
    );
  });

  it('downloads from the API root for an /api/v2/ URL', () => {
    assert.equal(
      cliDownloadUrl('https://analyzer.example.com/api/v2/', 'v1.0.0', 'x86_64-unknown-linux-gnu'),
      `https://analyzer.example.com/api/${RELEASE}`,
    );
  });
});
