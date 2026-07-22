# repo-guard

`repo-guard` is a small command-line scanner for two common repository mistakes:

1. committing credentials or private keys;
2. committing generated files, dependency directories, or unexpectedly large files.

It is designed for local checks and lightweight CI jobs. The runtime uses only the Python standard library.

## What it checks

The secret scanner currently recognises common AWS, GitHub, Slack, Stripe, and Google credentials, private-key headers, and suspicious hard-coded credential assignments. Findings include the file, line, column, a masked value, and a stable fingerprint. The original secret is never printed.

The repository audit also reports:

- `.env` files and other sensitive-looking filenames that are included in the scan;
- files above a configurable size threshold;
- dependency and build directories that are not ignored by Git;
- files that could not be read;
- symlinks, which are deliberately not followed.

When the target is inside a Git repository, `repo-guard` scans tracked files and untracked files that are not excluded by `.gitignore`. Use `--tracked-only` to inspect committed content only, or `--all-files` to walk the filesystem without consulting Git.

## Requirements

- Python 3.11 or newer
- Git is optional, but required for Git-aware discovery and `--tracked-only`

## Running from a checkout

```bash
python3 repoguard.py .
```

To install the command locally:

```bash
python3 -m pip install .
repo-guard .
```

## Common commands

Scan the current repository:

```bash
repo-guard .
```

Return JSON for another tool:

```bash
repo-guard . --format json --output repo-guard.json
```

Create a SARIF report for GitHub code scanning or another SARIF consumer:

```bash
repo-guard . --format sarif --output repo-guard.sarif
```

Scan only files already tracked by Git:

```bash
repo-guard . --tracked-only
```

Run only the secret checks:

```bash
repo-guard . --secrets-only
```

Treat additional categories as CI failures:

```bash
repo-guard . --fail-on secret,scan-error,suspicious-file,heavy-file,junk-dir
```

Exclude a path or allow a known test value:

```bash
repo-guard . \
  --exclude "tests/fixtures/**" \
  --allow "^example_[A-Za-z0-9_-]+$"
```

Run `repo-guard --help` for the complete option list.

## Configuration

If `.repoguard.toml` exists in the scanned directory, it is loaded automatically. A different file can be selected with `--config`; automatic loading can be disabled with `--no-config`.

```toml
[scan]
max_size_mb = 10
workers = 8
exclude = ["tests/fixtures/**"]
allow = ["^example_[A-Za-z0-9_-]+$"]
checks = ["secret", "suspicious-file", "heavy-file", "junk-dir"]

[policy]
fail_on = ["secret", "scan-error"]
```

A complete starting point is available in [`.repoguard.toml.example`](.repoguard.toml.example).

A single line can be suppressed when it contains an intentional fixture:

```python
password = "replace-me"  # repo-guard: allow
```

Use suppressions narrowly. Broad allow rules can hide real credentials.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | The scan completed and no configured failure category was found. |
| `1` | At least one category listed in `fail_on` was found. |
| `2` | The command or configuration was invalid, or the report could not be written. |

By default, secret findings and scan errors fail the command. Size, filename, and generated-directory findings are informational until they are added to `fail_on`.

## Scope and limitations

`repo-guard` is intentionally small. It does not inspect Git history, revoke credentials, validate whether a token is active, or replace a dedicated secret-scanning platform. Pattern matching can produce false positives and false negatives. For high-risk repositories, use it as an early local check alongside a mature scanner and repository-side secret protection.

Binary files are skipped. Text files are read line by line, so large source files do not need to be loaded into memory at once.

## Development

The test suite uses `unittest` and has no third-party requirements:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Useful validation commands:

```bash
python3 -m compileall -q src repoguard.py tests
python3 repoguard.py . --fail-on secret,scan-error
python3 -m pip install .
repo-guard --version
```

The package layout and design decisions are documented in [`docs/architecture.md`](docs/architecture.md). Contributions should include tests for behaviour changes.

## License

MIT. See [`LICENSE`](LICENSE).
