# Contributing to Exein Analyzer Scan

Thanks for your interest in `analyzer-scan`. This document explains how to report issues
and how the project is developed.

## Ways to contribute

### For everyone: open an issue

Anyone is welcome to:

- **Report a bug** using the [Bug report](https://github.com/exein-io/analyzer-scan/issues/new?template=bug_report.yaml)
  form.
- **Request a feature** using the [Feature request](https://github.com/exein-io/analyzer-scan/issues/new?template=feature_request.yaml)
  form.
- **Ask a question** — contact [support@exein.io](mailto:support@exein.io).

Please **do not** open public issues for security vulnerabilities. See
[SECURITY.md](../SECURITY.md) for how to report them privately.

### Pull requests

This repository is maintained by Exein. **Merges are internal-only** — pull requests are
reviewed and merged by the [@exein-io/infrastructure](https://github.com/orgs/exein-io/teams/infrastructure)
team (enforced via `CODEOWNERS`). Pull requests from outside the organization will not be
merged. If you have a fix or improvement in mind, please open an issue describing it so we
can pick it up.

## Development workflow (maintainers)

`analyzer-scan` is a bundled TypeScript GitHub Action. The compiled output in `dist/` is the
published entrypoint (see `action.yaml` → `main: dist/index.js`), so it is committed to the
repository and **must be kept in sync with `src/`**.

### Prerequisites

- **Node.js 24**
- **Yarn 4.9.1**, managed via Corepack:

  ```bash
  corepack enable
  ```

### Setup

```bash
yarn install --immutable
```

### Before you push

Run the full local pipeline:

```bash
yarn all   # runs lint + prettier + build
```

Then **rebuild and commit `dist/`**. CI runs a "Check dist/ is up-to-date" step that fails
if the committed `dist/` differs from a fresh `yarn build`:

```bash
yarn build
git add dist/
```

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and
PR titles, e.g. `feat: add SBOM scan type`, `fix: handle missing report path`,
`chore: bump dependencies`.

### Review

All changes require review and approval from `@exein-io/infrastructure` before merging.
