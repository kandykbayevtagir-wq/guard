# Architecture

The project keeps the command-line wrapper small and puts application code in an importable package.

## Modules

- `config.py` loads and validates `.repoguard.toml`.
- `discovery.py` selects files. Inside Git repositories it uses `git ls-files` so `.gitignore` behaviour comes from Git itself.
- `patterns.py` contains secret signatures and suppression rules.
- `scanner.py` coordinates metadata checks and concurrent text scanning.
- `models.py` defines the report data model.
- `reporters.py` renders text, JSON, and SARIF without changing scan results.
- `cli.py` merges configuration and command-line options, writes output, and applies exit policy.

The top-level `repoguard.py` file is only a compatibility launcher for people running the repository without installing it.

## Discovery rules

The default Git mode includes tracked files and untracked files that are not ignored. This catches a credential before it is added while avoiding noise from correctly ignored build output.

`--tracked-only` uses the Git index as its source. `--all-files` bypasses Git and walks the target directly. Filesystem discovery is also used when Git is unavailable or the target is not inside a repository.

Symlinks are listed but never followed. This prevents a repository scan from reading an unrelated file outside the requested tree.

## Secret handling

Each detector identifies the smallest part of a match that contains the credential. Reports contain only a masked representation and a SHA-256-derived fingerprint. Raw values remain in memory only while the relevant line is being inspected.

Configured allow patterns and the inline `repo-guard: allow` marker are applied after a detector matches. Placeholder handling is limited to the generic assignment detector; provider-specific token formats are still reported because a syntactically valid token should not be assumed harmless.

## Failure policy

Scanning and policy are separate. A report may contain low-severity findings while the process still exits successfully. The `fail_on` setting decides which categories return exit code 1. Read or discovery failures are represented as findings so JSON and SARIF consumers receive the same information as terminal users.
