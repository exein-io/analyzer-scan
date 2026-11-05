<p align="center">
  <img src="assets/header.png" alt="Project Logo"/>
</p>

GitHub Action for [Exein Analyzer](https://www.exein.io/platform/exein-analyzer). Scans pre-built firmware images and container images for vulnerabilities, supply chain risks, and security misconfigurations on every build, and can gate a release on its CVEs.

The action is a thin wrapper around the [Analyzer CLI](https://github.com/exein-io/homebrew-tools). It downloads the CLI, runs `analyzer scan new`, `analyzer scan gate` or `analyzer scan status`, and turns their JSON output into step outputs and a job summary. It makes no API calls of its own. A GitLab or Jenkins pipeline gets the same scan and gate by running the CLI directly.

## Supported firmware

| OS / Runtime | HW Platform |
|---|---|
| Linux | All supported platforms[^1] |
| Docker | All supported platforms |

[^1]: https://docs.kernel.org/arch/index.html

## Upgrading from v1

v2 runs the Analyzer CLI v1.0.0, which talks to the Analyzer v2 API only. That brings these breaking changes:

- `scan-type` takes `docker` or `linux`. ESP-IDF (`idf`) and SBOM (`sbom`) scans stay on `analyzer-scan@v1`.
- `cli-version` defaults to `v1.0.0`, the CLI release v2 is built for, instead of `latest`. A 0.x CLI does not work with v2.
- The API picks the analyses of a scan by its type. v1 passed a fixed list per type.
- `download-report` and `download-sbom` removed: use `gate: 'true'` with `fail-on: none`, which waits for the scan and [downloads the SBOM, VEX and report](#download-the-report-sbom-and-vex) without failing on CVEs. A step that still sets either one to `true` fails at once with that hint.

New in v2: `object-key` to name the object by a key instead of its UUID, `build-vex`, and the [release gate](#release-gate).

## Prerequisites

- An Exein Analyzer account with an API key
- An object to scan into. Give its UUID with `object-id`, or give `object-key` and the CLI reuses the object with that key or makes it.

## Usage

The action expects a pre-built firmware image. Build toolchains vary widely across projects (Docker, Yocto, Buildroot, etc.), so the action is designed to complement your existing build pipeline rather than replace or incorporate it.

By default (`gate: false`), the action uploads the image with `analyzer scan new`, which starts a scan, and returns without waiting for it. It sets `scan-id`, `scan-url` and `object-id`, logs the scan's link, and writes the upload to the job summary. A later step can [gate the scan](#gate-a-scan-made-earlier) by its `scan-id`.

### Scan a firmware image

```yaml
- uses: exein-io/analyzer-scan@v2
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    object-id: '14e383ce-947f-11f0-8a00-0b80b65337cb'
    scan-type: linux
    file-path: ./image.tar.gz
```

### Scan after a Docker build

```yaml
- uses: docker/build-push-action@v5
  with:
    context: .
    outputs: type=docker,dest=/tmp/image.tar

- uses: exein-io/analyzer-scan@v2
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    object-id: '14e383ce-947f-11f0-8a00-0b80b65337cb'
    scan-type: docker
    file-path: /tmp/image.tar
```

### Download the report, SBOM and VEX

To wait for the scan and keep its evidence without gating on its CVEs, run the [release gate](#release-gate) with `fail-on: none`. The step waits for the scan, saves the SBOM, VEX and PDF report in the working directory, and sets their paths. The CVEs don't fail the step. A scan that ended in `error` or `canceled`, or a missing SBOM or VEX, still does.

```yaml
- uses: exein-io/analyzer-scan@v2
  id: scan
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    gate: 'true'
    fail-on: none
    object-id: '14e383ce-947f-11f0-8a00-0b80b65337cb'
    scan-type: linux
    file-path: ./build/firmware.tar.gz

- run: 'echo "Scan results: ${{ steps.scan.outputs.scan-url }}"'

- uses: actions/upload-artifact@v4
  with:
    name: scan-artifacts
    path: |
      ${{ steps.scan.outputs.report-path }}
      ${{ steps.scan.outputs.sbom-path }}
      ${{ steps.scan.outputs.vex-path }}
```

### Scan multiple images in parallel

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - name: gateway
            object-id: 'a1b2c3d4-5678-9abc-def0-1234567890ab'
            scan-type: linux
            file-path: ./build/gateway.bin
          - name: sensor
            object-key: sensor-firmware
            scan-type: linux
            file-path: ./build/sensor.tar.gz
          - name: api-server
            object-id: 'a9b0c1d2-3456-7890-abcd-ef1234567890'
            scan-type: docker
            file-path: ./build/api-server.tar
    steps:
      - uses: actions/checkout@v7

      - uses: exein-io/analyzer-scan@v2
        with:
          api-key: ${{ secrets.ANALYZER_API_KEY }}
          object-id: ${{ matrix.object-id }}
          object-key: ${{ matrix.object-key }}
          scan-type: ${{ matrix.scan-type }}
          file-path: ${{ matrix.file-path }}
```

## Release gate

With `gate: 'true'`, the action gates the release on its CVEs. It runs two CLI commands:

1. `analyzer scan new` uploads the image to the object, with the build's VEX when `build-vex` is set, and starts a scan. The action sets `scan-id`, `scan-url` and `object-id` as soon as it returns.
2. `analyzer scan gate` waits until the scan finishes and its CVE classification settles, downloads the SBOM, VEX and PDF report, and decides. The step fails when a CVE at `fail-on` or above is reachable or unresolved, when the scan failed, or when the SBOM or VEX is missing.

The CLI makes the decision, and its exit code sets the step's outcome. The action maps the inputs to flags, and the CLI's JSON to the outputs and the job summary. The CLI prints its progress while it waits, and the step shows it in the job log as it comes.

```yaml
- uses: exein-io/analyzer-scan@v2
  id: gate
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    gate: 'true'
    object-key: gateway-firmware
    scan-type: linux
    file-path: ./build/firmware.tar.gz
    fail-on: high
```

The job summary has a table per severity of all, reachable, unreachable and unresolved CVEs. It marks the counts that block, lists why the gate failed, and links the scan.

With the default `gate: false`, the action runs step 1 only, sets `scan-id`, `scan-url` and `object-id`, and succeeds without waiting. A later step gates the scan with `gate: 'true'` and `scan-id`.

With `gate: status` and `scan-id`, the action [checks the scan](#check-a-scan) without waiting, so a later step gates it only once it has finished.

### Send the build's VEX

A build that already knows some CVEs don't apply sends its CycloneDX VEX with `build-vex`. The CLI sends it in the same upload, before the image. Its statements set the states of the scan's CVEs: a CVE it marks `not_affected` or `resolved` counts as unreachable, so it does not block, and the downloaded VEX carries the statement.

```yaml
- uses: exein-io/analyzer-scan@v2
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    gate: 'true'
    object-key: gateway-firmware
    scan-type: linux
    file-path: ./build/firmware.tar.gz
    build-vex: ./build/firmware.vex.json
    fail-on: high
```

The file must be one JSON object of at most 64 MiB. The CLI checks that before it uploads anything, so a file that is missing, too large or not a JSON object fails the step at once, not after the image uploads. Every mode that uploads sends it. With `scan-id` nothing is uploaded, so `build-vex` is refused there.

### Draft release flow

Build the image, publish it as a draft release, gate it, and promote the release only when the gate passes. No one gets a release that has not passed the gate.

#### In one job

The gate step waits for the scan, so the job runs as long as the CVE analysis takes.

```yaml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    # A CVE analysis can take hours; GitHub-hosted jobs stop at 6 h.
    timeout-minutes: 360
    steps:
      - uses: actions/checkout@v7

      # 1. Build
      - run: ./build.sh # writes build/firmware.tar.gz

      # 2. A draft release, which no one gets yet
      - name: Draft the release
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh release create "$GITHUB_REF_NAME" --draft --verify-tag build/firmware.tar.gz

      # 3. Scan and gate
      - uses: exein-io/analyzer-scan@v2
        id: gate
        with:
          api-key: ${{ secrets.ANALYZER_API_KEY }}
          gate: 'true'
          object-key: gateway-firmware
          scan-type: linux
          file-path: build/firmware.tar.gz
          fail-on: high

      # The evidence goes on the draft whether the gate passed or not.
      - name: Attach the SBOM, VEX and report
        if: always() && steps.gate.outputs.scan-id != ''
        env:
          GH_TOKEN: ${{ github.token }}
          SBOM: ${{ steps.gate.outputs.sbom-path }}
          VEX: ${{ steps.gate.outputs.vex-path }}
          REPORT: ${{ steps.gate.outputs.report-path }}
        run: |
          for file in "$SBOM" "$VEX" "$REPORT"; do
            if [ -n "$file" ]; then gh release upload "$GITHUB_REF_NAME" "$file" --clobber; fi
          done

      # 4. Promote: runs only when the gate passed
      - name: Publish the release
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh release edit "$GITHUB_REF_NAME" --draft=false
```

A failed gate leaves the release a draft, with the evidence attached for review.

#### Upload in the build, gate on a schedule

No job waits for the CVE analysis. The build job uploads the image with the default `gate: false`, and keeps the scan id from `steps.upload.outputs.scan-id` in the draft's notes. A scheduled workflow checks the scan of the oldest draft with `gate: status`, gates the draft once its scan has finished, and promotes it when it passes.

`.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - run: ./build.sh # writes build/firmware.tar.gz

      - uses: exein-io/analyzer-scan@v2
        id: upload
        with:
          api-key: ${{ secrets.ANALYZER_API_KEY }}
          object-key: gateway-firmware
          scan-type: linux
          file-path: build/firmware.tar.gz

      - name: Draft the release, with its scan id
        env:
          GH_TOKEN: ${{ github.token }}
          SCAN_ID: ${{ steps.upload.outputs.scan-id }}
        run: |
          gh release create "$GITHUB_REF_NAME" --draft --verify-tag \
            --notes "Analyzer scan: $SCAN_ID" build/firmware.tar.gz
```

`.github/workflows/gate.yml`:

```yaml
name: Gate draft releases

on:
  schedule:
    - cron: '7,37 * * * *'
  workflow_dispatch:

permissions:
  contents: write

concurrency:
  group: analyzer-gate

jobs:
  gate:
    runs-on: ubuntu-latest
    env:
      GH_TOKEN: ${{ github.token }}
      GH_REPO: ${{ github.repository }}
    steps:
      # The oldest draft not gated yet. Releases go out in build order, so later drafts wait for it.
      - name: Find the next draft
        id: draft
        run: |
          drafts=$(gh release list --json tagName,isDraft,createdAt \
            --jq '[.[] | select(.isDraft)] | sort_by(.createdAt) | .[].tagName')
          for tag in $drafts; do
            notes=$(gh release view "$tag" --json body --jq .body)
            scan=$(sed -n 's/^Analyzer scan: //p' <<<"$notes")
            if [ -z "$scan" ] || grep -q '^Analyzer gate: failed' <<<"$notes"; then continue; fi
            { echo "tag=$tag"; echo "scan-id=$scan"; } >>"$GITHUB_OUTPUT"
            break
          done

      # Reads the scan's status, and does not wait for it.
      - uses: exein-io/analyzer-scan@v2
        id: status
        if: steps.draft.outputs.scan-id != ''
        with:
          api-key: ${{ secrets.ANALYZER_API_KEY }}
          gate: status
          scan-id: ${{ steps.draft.outputs.scan-id }}

      # Until the scan has finished, later runs check it again.
      - uses: exein-io/analyzer-scan@v2
        id: gate
        if: steps.status.outputs.finished == 'true'
        with:
          api-key: ${{ secrets.ANALYZER_API_KEY }}
          gate: 'true'
          scan-id: ${{ steps.draft.outputs.scan-id }}
          fail-on: high
          timeout: 30m

      - name: Attach the SBOM, VEX and report
        if: always() && steps.gate.outputs.scan-id != ''
        env:
          TAG: ${{ steps.draft.outputs.tag }}
          SBOM: ${{ steps.gate.outputs.sbom-path }}
          VEX: ${{ steps.gate.outputs.vex-path }}
          REPORT: ${{ steps.gate.outputs.report-path }}
        run: |
          for file in "$SBOM" "$VEX" "$REPORT"; do
            if [ -n "$file" ]; then gh release upload "$TAG" "$file" --clobber; fi
          done

      - name: Publish the release
        if: steps.gate.outcome == 'success'
        env:
          TAG: ${{ steps.draft.outputs.tag }}
        run: gh release edit "$TAG" --draft=false

      # Later runs skip this draft. To gate it again, drop the line from its notes.
      - name: Mark the draft as failed
        if: failure() && steps.gate.outcome == 'failure'
        env:
          TAG: ${{ steps.draft.outputs.tag }}
        run: |
          notes=$(gh release view "$TAG" --json body --jq .body)
          gh release edit "$TAG" --notes "$notes"$'\n'"Analyzer gate: failed"
```

### Gate a scan made earlier

With `scan-id` instead of `object-id` or `object-key`, the gate uploads nothing and gates that scan. That is the second half of the flow above. A gate that timed out also names the scan id in its error, so a second run can pick it up.

```yaml
- uses: exein-io/analyzer-scan@v2
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    gate: 'true'
    scan-id: ${{ inputs.scan-id }}
```

### Check a scan

With `gate: status` and `scan-id`, the action runs `analyzer scan status` once. It sets `scan-status` and `finished`, and writes one line to the job summary. It uploads nothing and decides nothing. A scan that ended in `error` or was `canceled` does not fail the step. The gate decides on that. A refused API key or an unknown scan fails the step with the CLI's error. The CLI retries through outages, and the step stops it after `timeout` or 20m, whichever is shorter.

```yaml
- uses: exein-io/analyzer-scan@v2
  id: status
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    gate: status
    scan-id: ${{ inputs.scan-id }}

- uses: exein-io/analyzer-scan@v2
  if: steps.status.outputs.finished == 'true'
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    gate: 'true'
    scan-id: ${{ inputs.scan-id }}
```

### How the gate decides

A CVE blocks when it is at `fail-on` or above and reachable or unresolved. Reachable means exploitable. Unresolved means in triage or not classified yet. A CVE whose VEX state is `not_affected`, `resolved`, `resolved_with_pedigree` or `false_positive` is unreachable and never blocks. Neither does a CVE with no critical, high, medium or low rating. The blocking count matches a jq filter over the downloaded VEX that counts the CVEs at `fail-on` or above in none of those four states.

Docker images are not classified for reachability yet. Until they are, each CVE of a Docker scan counts as unresolved, so every one at `fail-on` or above blocks.

The gate decides on final counts only, after the scan finished and its classification settled.

A scan that ended in `error` or was `canceled` fails the gate, whatever its counts. The gate still reads the counts as they stand, downloads what the scan has, and sets its outputs.

A CVE analysis of a large image takes hours. A Home Assistant image took 3 to 5 hours. The CLI waits and retries: it polls less often while nothing changes, and rides out outages of up to 15 minutes in a row, such as a platform deploy. `timeout` counts from the start of the step, upload included. When it runs out, the step fails with `scan-id` set, so a later run can gate that scan.

| Outcome | The step |
|---|---|
| The gate passed | succeeds |
| The gate failed: blocking CVEs, a scan that ended `error` or `canceled`, or a missing SBOM or VEX | fails with the reasons. The outputs are set, and the job summary has the counts |
| No result: a refused API key, a refused upload, a scan that gets no CVE counts, or the timeout | fails with the CLI's error. `scan-id` is set once the scan exists. After a timeout, the error says how to gate the scan later |

The SBOM, VEX and report land in the working directory as `<scan-id>-sbom.json`, `<scan-id>-vex.json` and `<scan-id>-report.pdf`. The SBOM and VEX are the release's evidence, so the gate fails when either is missing. The PDF report can lag while it renders, or while the scan has no score yet, and the CLI waits for it until `timeout`. A missing PDF report only warns, since a scan that gets no score gets no report. The summary says which file is missing and why.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api-key` | yes | — | Exein Analyzer API key |
| `api-url` | no | `https://analyzer.exein.io/api/` | API root, ending in `/api`, for on-prem deployments. The `/api/v2` form works too. The CLI downloads from `<api root>/releases/` |
| `object-id` | one of the two, unless `scan-id` | — | UUID of the object to upload to |
| `object-key` | one of the two, unless `scan-id` | — | Key of the object to upload to, made when the key is new. Lowercase letters and digits in words joined by single hyphens, at most 63 characters, such as `gateway-firmware-arm64` |
| `object-name` | no | the key | Name of the object when `object-key` is new |
| `scan-type` | yes, unless `scan-id` | — | `docker` or `linux` |
| `file-path` | yes, unless `scan-id` | — | Path to the image |
| `build-vex` | no | — | Path to the [build's CycloneDX VEX](#send-the-builds-vex), one JSON object of at most 64 MiB, sent before the image. A CVE it marks `not_affected` or `resolved` counts as unreachable. Not with `scan-id` |
| `cli-version` | no | `v1.0.0` | [Analyzer CLI](https://github.com/exein-io/homebrew-tools) release to run. v2 of this action needs CLI v1 |
| `timeout` | no | `5h30m` | How long the step waits for the scan, counted from its start, such as `5h30m`, `90m` or `45s`. Read by the gate, and by `gate: status`, which waits 20m at most. `gate: false` doesn't wait. Keep it under the job's `timeout-minutes`, so the step can report the scan id |

Release gate inputs:

| Input | Required | Default | Description |
|---|---|---|---|
| `gate` | no | `false` | `false` only uploads the image, for a later gate with `scan-id`. `true` runs the [release gate](#release-gate). `status` [checks the scan](#check-a-scan) of `scan-id`, and fails only when it can't read it |
| `scan-id` | with `gate: status` | — | Gate this scan made earlier instead of uploading an image, with `gate: 'true'`. The scan to check, with `gate: status` |
| `fail-on` | no | `critical` | Lowest severity that blocks: `critical`, `high`, `medium`, or `low`. `none` reports only, for pipelines that gate on something else: no CVE fails the step, and `blocking` is `0`. Read only by `gate: 'true'` |

The gate always downloads the SBOM, VEX and report.

## Outputs

| Output | Description |
|---|---|
| `scan-id` | UUID of the created scan |
| `scan-url` | Direct link to scan results in the Analyzer UI |
| `report-path` | Gate: path to the downloaded PDF report |
| `sbom-path` | Gate: path to the downloaded SBOM JSON |
| `object-id` | UUID of the object |
| `vex-path` | Gate: path to the downloaded VEX JSON |
| `cve-counts` | Gate: the CVE counts, as JSON: `all`, `reachable`, `unreachable` and `unresolved` per severity, with `classification` and `settled` |
| `blocking` | Gate: number of blocking CVEs, empty when the scan has no counts. The step's outcome is the decision: a failed scan or a missing SBOM or VEX fails the gate with `blocking` at `0` |
| `scan-status` | Gate and `gate: status`: the scan's status, `pending`, `in-progress`, `success`, `error` or `canceled` |
| `finished` | `gate: status`: `'true'` once the scan ended in `success`, `error` or `canceled`, `'false'` while it runs |

## Analyses

A scan runs the analyses the Analyzer API picks for its image type. The action and the CLI don't choose them.

## License

Apache-2.0
