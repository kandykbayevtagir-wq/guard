from __future__ import annotations

import argparse
from pathlib import Path
import sys

from . import __version__
from .config import ConfigError, RepoGuardConfig, load_config
from .models import Category
from .reporters import render_json, render_sarif, render_text
from .scanner import scan


VALID_CATEGORIES = {category.value for category in Category}


def _csv_categories(value: str) -> set[str]:
    values = {item.strip() for item in value.split(",") if item.strip()}
    unknown = values - VALID_CATEGORIES
    if unknown:
        raise argparse.ArgumentTypeError(
            "unknown categories: " + ", ".join(sorted(unknown))
        )
    return values


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-guard",
        description="Find likely secrets and repository bloat before they are committed.",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Report format (default: text)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Compatibility alias for --format json",
    )
    parser.add_argument("--output", type=Path, help="Write the report to this file")
    parser.add_argument(
        "--max-size-mb",
        type=float,
        help="Threshold for heavy-file findings",
    )
    discovery = parser.add_mutually_exclusive_group()
    discovery.add_argument(
        "--tracked-only",
        action="store_true",
        default=None,
        help="Scan files already tracked by Git only",
    )
    discovery.add_argument(
        "--all-files",
        action="store_true",
        default=None,
        help="Ignore .gitignore and walk the filesystem directly",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Exclude a path pattern; may be repeated",
    )
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="REGEX",
        help="Allow a matching line or value; may be repeated",
    )
    parser.add_argument(
        "--fail-on",
        type=_csv_categories,
        help="Comma-separated finding categories that produce exit code 1",
    )
    parser.add_argument(
        "--secrets-only",
        action="store_true",
        help="Disable filename, size, and generated-directory checks",
    )
    parser.add_argument("--workers", type=int, help="Number of scanner worker threads")
    parser.add_argument("--config", type=Path, help="Path to a TOML config file")
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Do not load .repoguard.toml",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def _config_for(args: argparse.Namespace, target: Path) -> RepoGuardConfig:
    base = target.expanduser()
    config_root = base if base.is_dir() else base.parent
    config_path = args.config
    if config_path is None and not args.no_config:
        candidate = config_root / ".repoguard.toml"
        if candidate.is_file():
            config_path = candidate

    config = load_config(config_path) if config_path else RepoGuardConfig()

    if args.max_size_mb is not None:
        config.max_size_mb = args.max_size_mb
    if args.workers is not None:
        config.workers = args.workers
    if args.tracked_only is not None:
        config.tracked_only = True
        config.all_files = False
    if args.all_files is not None:
        config.all_files = True
        config.tracked_only = False
    if args.exclude:
        config.excludes.extend(args.exclude)
    if args.allow:
        config.allow_patterns.extend(args.allow)
    if args.fail_on is not None:
        config.fail_on = args.fail_on
    if args.secrets_only:
        config.checks = {Category.SECRET.value}

    config.validate()
    return config


def _render(report_format: str, report, color: bool) -> str:
    if report_format == "json":
        return render_json(report)
    if report_format == "sarif":
        return render_sarif(report)
    return render_text(report, color=color)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    target = Path(args.path)

    try:
        config = _config_for(args, target)
    except ConfigError as exc:
        parser.error(str(exc))

    report = scan(target, config, version=__version__)
    report_format = "json" if args.json else args.format
    output = _render(
        report_format,
        report,
        color=(not args.no_color and sys.stdout.isatty() and args.output is None),
    )

    try:
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
    except OSError as exc:
        print(f"repo-guard: could not write report: {exc}", file=sys.stderr)
        return 2

    return 1 if report.has_categories(config.fail_on) else 0


def entrypoint() -> None:
    raise SystemExit(main())
