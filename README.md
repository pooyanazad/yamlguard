# yamlguard

[![CI](https://github.com/pooyanazad/yamlguard/actions/workflows/docker-build.yml/badge.svg)](https://github.com/pooyanazad/yamlguard/actions/workflows/docker-build.yml)
[![PyPI](https://img.shields.io/pypi/v/yamlguard.svg)](https://pypi.org/project/yamlguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Check your YAML files before you commit or deploy them. **yamlguard** catches syntax errors and style issues, and can scan supported infrastructure files for security problems with Checkov.

Install the `yamlguard` CLI from PyPI, or use the Docker image `pooyanazad/yamlguard`. Both run the same validator; Docker includes Checkov.

## Install and run

### Python

Requires Python 3.9 or newer. Create a virtual environment so the installation stays separate from your system Python.

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install yamlguard
```

**Windows — Command Prompt:**

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install yamlguard
```

In PowerShell, activate the environment with `.\.venv\Scripts\Activate.ps1` instead.

Then check a file:

```bash
yamlguard config.yaml
```

The base installation checks syntax with PyYAML and style with yamllint. To add security scanning, install the optional extra in the same environment:

```bash
python -m pip install "yamlguard[security]"
yamlguard deployment.yaml
```

Checkov checks supported infrastructure formats, such as Kubernetes manifests. Without Checkov, syntax and style checks still run, with a warning that security scanning was skipped.

### Docker

With Docker installed, open a terminal in the folder containing your YAML files and run the command for your shell. On Windows, use Docker Desktop with Linux containers.

**Linux / macOS:**

```bash
docker run --rm -v "$(pwd):/data:ro" pooyanazad/yamlguard:latest config.yaml
```

**Windows — PowerShell:**

```powershell
docker run --rm -v "${PWD}:/data:ro" pooyanazad/yamlguard:latest config.yaml
```

**Windows — Command Prompt:**

```bat
docker run --rm -v "%cd%:/data:ro" pooyanazad/yamlguard:latest config.yaml
```

These commands mount your current folder read-only at `/data`. Use paths within that folder, such as `config.yaml` or `./configs/`. Files must be readable by the container's non-root user.

Images support `linux/amd64` and `linux/arm64`. The examples use `latest`, which follows new publications and scheduled rebuilds. For reproducible CI runs, replace `:latest` with the versioned tag shown under **Latest release**.

## Everyday examples

```bash
yamlguard config.yaml                        # Check one file
yamlguard config.yaml deployment.yml         # Check several files
yamlguard ./configs/                         # Check all .yaml and .yml files recursively
yamlguard "./configs/**/*.yaml"              # Let yamlguard expand the pattern
yamlguard ./configs/ --no-security            # Run syntax and style checks only
yamlguard deployment.yaml --timeout 60       # Limit each validator subprocess to 60 seconds
```

With Docker, pass these same arguments after the image name. For example, replace `config.yaml` in the Docker command with `./configs/ --no-security`.

Run `yamlguard --help` for all options. You can also run the CLI as `python -m yamlguard`. Missing paths are skipped with a warning; the command fails if no files remain.

## Reports and exit codes

Text output is the default. For CI or other tools, export a report:

```bash
yamlguard ./configs/ --format json > results.json
yamlguard ./configs/ --format junit > test-results.xml
yamlguard ./configs/ --format sarif > results.sarif
```

JSON returns one object for one file or an array for several files. JUnit XML works with test-report viewers; SARIF 2.1.0 works with compatible code-scanning tools. Upload reports through your CI configuration.

In version 3.5.0 and newer, machine-readable reports go to stdout and warnings go to stderr.

| Exit code | Meaning |
| --- | --- |
| `0` | No findings, or only Medium / Low / Info findings. |
| `1` | Critical / High findings, a validator failure, no matching files, or a required dependency is missing. |
| `2` | Invalid command-line arguments. |

Syntax errors are Critical. Lint errors are Medium and warnings are Low, so **lint findings alone do not fail the command**. Checkov findings without a severity default to High.

- **Empty, comment-only, and explicit null documents** are syntactically valid (`syntax_valid: true` in JSON) and emit an `Info` notice without failing the command.
- **Readable files with syntax errors** still run yamllint (and Checkov when enabled) so you retain lint feedback alongside the syntax error.
- **Unreadable, non-UTF-8, and binary files** are `Critical` validation failures (`syntax_valid: false`, exit `1`) and skip downstream yamllint and Checkov scans. *(Behavior change: earlier versions reported binary files as a non-failing `Medium` warning.)*

## Project links

[Releases](https://github.com/pooyanazad/yamlguard/releases) · [Report an issue](https://github.com/pooyanazad/yamlguard/issues) · [Contributing](CONTRIBUTING.md) · [Maintainer release guide](release-notes/README.md)

## Latest release

<!-- RELEASE_NOTES_START -->
### v3.5.1-20261011 — 2026-10-11

**Changes since `v3.5.0-20261011`** (7 non-merge commits).

- Build and maintenance: 2 commit(s).
- Fixes: 3 commit(s).
- Documentation: 2 commit(s).

[Full changelog](https://github.com/pooyanazad/yamlguard/compare/v3.5.0-20261011...v3.5.1-20261011)

**Docker image:** `pooyanazad/yamlguard:v3.5.1-20261011`

<!-- RELEASE_NOTES_END -->
