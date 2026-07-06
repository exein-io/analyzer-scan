# Exein Analyzer Scan

GitHub Action for scanning firmware images with [Exein Analyzer](https://www.exein.io/platform/exein-analyzer).

## Supported Firmware

| OS / Framework / Runtime | HW Platform | Support[^1] |
|---|---|---|
| Linux | All supported platforms[^2] | GA |
| Docker | All supported platforms | GA |
| ESP-IDF | xtensa | GA |
| ESP-IDF | riscv32 | GA |
| ESP-IDF (PlatformIO) | xtensa | GA |
| ESP-IDF (PlatformIO) | riscv32 | GA |
| FreeRTOS | All supported platforms[^3] | GA Premium Service |
| ZephyrOS | All supported platforms[^4] | Roadmap |
| UEFI | x86_64 | Roadmap |
| VxWorks (v5 and v6) | arm32 | Roadmap |
| VxWorks (v5 and v6) | ppc | Roadmap |

[^1]: **GA**: Generally Available. **Roadmap**: Scheduled in Product Roadmap.
[^2]: https://docs.kernel.org/arch/index.html
[^3]: https://www.freertos.org/Documentation/02-Kernel/03-Supported-devices/00-Supported-devices
[^4]: https://docs.zephyrproject.org/latest/boards/index.html

## Prerequisites

- An Exein Analyzer account with an API key
- An object already created in the Analyzer platform — use the [Analyzer CLI](https://github.com/exein-io/analyzer-cli) or web UI to create one

## Usage

The action expects a pre-built firmware image. Build toolchains vary widely across projects (Docker, Yocto, Buildroot, ESP-IDF, etc.), so the action is designed to complement your existing build pipeline rather than replace or incorporate it.

### Scan a firmware image

```yaml
- uses: exein-io/analyzer-scan@v1
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

- uses: exein-io/analyzer-scan@v1
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    object-id: '14e383ce-947f-11f0-8a00-0b80b65337cb'
    scan-type: docker
    file-path: /tmp/image.tar
```

### Download report and SBOM

```yaml
- uses: exein-io/analyzer-scan@v1
  id: scan
  with:
    api-key: ${{ secrets.ANALYZER_API_KEY }}
    object-id: '14e383ce-947f-11f0-8a00-0b80b65337cb'
    scan-type: linux
    file-path: ./build/firmware.tar.gz
    download-report: 'true'
    download-sbom: 'true'
    analysis: |
      info
      kernel
      cve
      software-bom

- run: echo "Scan results: ${{ steps.scan.outputs.scan-url }}"

- uses: actions/upload-artifact@v4
  with:
    name: scan-artifacts
    path: |
      ${{ steps.scan.outputs.report-path }}
      ${{ steps.scan.outputs.sbom-path }}
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
            object-id: 'e5f6g7h8-9012-3456-7890-abcdef123456'
            scan-type: idf
            file-path: ./build/sensor.bin
          - name: api-server
            object-id: 'i9j0k1l2-3456-7890-abcd-ef1234567890'
            scan-type: docker
            file-path: ./build/api-server.tar
    steps:
      - uses: actions/checkout@v4

      - uses: exein-io/analyzer-scan@v1
        with:
          api-key: ${{ secrets.ANALYZER_API_KEY }}
          object-id: ${{ matrix.object-id }}
          scan-type: ${{ matrix.scan-type }}
          file-path: ${{ matrix.file-path }}
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api-key` | yes | — | Exein Analyzer API key |
| `api-url` | no | `https://analyzer.exein.io/api` | Base API URL |
| `object-id` | yes | — | UUID of the Analyzer object to scan against |
| `scan-type` | yes | — | `docker`, `linux`, or `idf` |
| `file-path` | yes | — | Path to the firmware image file |
| `analysis` | no | all for scan type | Newline-separated list of [analysis types](#analysis-types) to run |
| `download-report` | no | `false` | Download PDF report after scan |
| `download-sbom` | no | `false` | Download SBOM JSON after scan |
| `cli-version` | no | `latest` | Pin [Analyzer CLI](https://github.com/exein-io/analyzer-cli) version (e.g. `v1.0.0`) |

## Outputs

| Output | Description |
|---|---|
| `scan-id` | UUID of the created scan |
| `scan-url` | Direct link to scan results in the Analyzer UI |
| `report-path` | Path to downloaded PDF report (set when `download-report: true`) |
| `sbom-path` | Path to downloaded SBOM JSON (set when `download-sbom: true`) |

## Analysis Types

Available analysis types vary by scan type:

| Analysis | `docker` | `linux` | `idf` |
|---|---|---|---|
| `info` | yes | yes | yes |
| `cve` | yes | yes | yes |
| `software-bom` | yes | yes | yes |
| `password-hash` | yes | yes | — |
| `crypto` | yes | yes | — |
| `malware` | yes | yes | — |
| `hardening` | yes | yes | — |
| `capabilities` | yes | yes | — |
| `kernel` | — | yes | — |
| `symbols` | — | — | yes |
| `tasks` | — | — | yes |
| `stack-overflow` | — | — | yes |

When `analysis` is not specified, all available types for the chosen scan type are run.

## License

Apache-2.0
