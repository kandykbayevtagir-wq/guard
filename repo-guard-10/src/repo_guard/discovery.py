from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess


@dataclass(slots=True)
class DiscoveryResult:
    files: list[Path] = field(default_factory=list)
    source: str = "filesystem"
    errors: list[str] = field(default_factory=list)


def _normalise_pattern(pattern: str) -> str:
    return pattern.strip().replace("\\", "/").strip("/")


def is_excluded(relative_path: Path, patterns: list[str]) -> bool:
    value = relative_path.as_posix().lstrip("./")
    pure_path = PurePosixPath(value)
    for raw_pattern in patterns:
        pattern = _normalise_pattern(raw_pattern)
        if not pattern:
            continue
        if fnmatch.fnmatch(value, pattern) or pure_path.match(pattern):
            return True
        if "/" not in pattern and any(
            fnmatch.fnmatch(part, pattern) for part in pure_path.parts
        ):
            return True
    return False


def find_git_root(target: Path) -> Path | None:
    if shutil.which("git") is None:
        return None
    cwd = target if target.is_dir() else target.parent
    process = subprocess.run(
        ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        return None
    root = process.stdout.strip()
    return Path(root).resolve() if root else None


def _discover_with_git(
    target: Path,
    scan_root: Path,
    git_root: Path,
    tracked_only: bool,
    excludes: list[str],
) -> DiscoveryResult:
    try:
        target_relative = target.absolute().relative_to(git_root)
    except ValueError:
        return DiscoveryResult(errors=["target is outside the detected Git repository"])

    pathspec = target_relative.as_posix() or "."
    command = ["git", "-C", str(git_root), "ls-files", "-z", "--cached"]
    if not tracked_only:
        command.extend(["--others", "--exclude-standard"])
    command.extend(["--", pathspec])

    process = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        message = process.stderr.decode("utf-8", errors="replace").strip()
        return DiscoveryResult(
            source="git",
            errors=[f"git file discovery failed: {message or 'unknown error'}"],
        )

    files: list[Path] = []
    for raw_path in process.stdout.split(b"\0"):
        if not raw_path:
            continue
        repository_relative = Path(os.fsdecode(raw_path))
        absolute_path = (git_root / repository_relative).absolute()
        try:
            scan_relative = absolute_path.relative_to(scan_root)
        except ValueError:
            continue
        if is_excluded(scan_relative, excludes):
            continue
        if absolute_path.exists() or absolute_path.is_symlink():
            files.append(absolute_path)

    return DiscoveryResult(files=sorted(set(files)), source="git")


def _discover_with_filesystem(
    target: Path,
    scan_root: Path,
    excludes: list[str],
) -> DiscoveryResult:
    if target.is_file() or target.is_symlink():
        relative = target.relative_to(scan_root)
        files = [] if is_excluded(relative, excludes) else [target]
        return DiscoveryResult(files=files, source="filesystem")

    files: list[Path] = []
    errors: list[str] = []

    def on_error(exc: OSError) -> None:
        errors.append(f"cannot walk {exc.filename or target}: {exc.strerror or exc}")

    for root, dirs, names in os.walk(target, topdown=True, followlinks=False, onerror=on_error):
        root_path = Path(root)
        kept_dirs: list[str] = []
        for directory in dirs:
            candidate = root_path / directory
            relative = candidate.relative_to(scan_root)
            if is_excluded(relative, excludes):
                continue
            if candidate.is_symlink():
                files.append(candidate)
                continue
            kept_dirs.append(directory)
        dirs[:] = kept_dirs

        for name in names:
            candidate = root_path / name
            relative = candidate.relative_to(scan_root)
            if not is_excluded(relative, excludes):
                files.append(candidate)

    return DiscoveryResult(files=sorted(files), source="filesystem", errors=errors)


def discover_files(
    target: Path,
    *,
    tracked_only: bool,
    all_files: bool,
    excludes: list[str],
) -> tuple[Path, DiscoveryResult]:
    resolved_target = target.expanduser().absolute()
    if not resolved_target.exists() and not resolved_target.is_symlink():
        scan_root = resolved_target.parent
        return scan_root, DiscoveryResult(errors=[f"path does not exist: {resolved_target}"])

    scan_root = (
        resolved_target
        if resolved_target.is_dir() and not resolved_target.is_symlink()
        else resolved_target.parent
    )
    git_root = None if all_files or resolved_target.is_symlink() else find_git_root(resolved_target)
    if git_root is not None:
        result = _discover_with_git(
            resolved_target,
            scan_root,
            git_root,
            tracked_only,
            excludes,
        )
        return scan_root, result
    elif tracked_only:
        return scan_root, DiscoveryResult(
            source="git",
            errors=["--tracked-only requires a Git repository and the git executable"],
        )

    return scan_root, _discover_with_filesystem(resolved_target, scan_root, excludes)
