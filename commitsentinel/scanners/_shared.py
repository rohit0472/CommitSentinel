"""Shared, scanner-agnostic helpers for walking a repo tree.

This is plumbing, not scanner logic — importing it doesn't violate "scanners
never know about each other," since no scanner imports another scanner here,
they only share this filesystem helper.
"""

from __future__ import annotations

import os
from pathlib import Path

IGNORED_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "__pycache__",
    ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache",
    ".next", ".cache", "target", ".idea", ".vscode",
}

# Extensions we don't bother reading as text — binary content produces
# either decode errors (harmless) or garbage entropy noise (not harmless).
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav",
    ".db", ".sqlite", ".sqlite3",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB — not worth scanning line-by-line beyond this


def iter_files(repo_path: Path):
    """Yield every non-ignored, non-binary, reasonably-sized file under repo_path."""
    for root, dirs, _files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.endswith(".egg-info")]
        for name in _files:
            path = Path(root) / name
            if path.suffix.lower() in BINARY_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield path


def read_text_lines(path: Path) -> list[str] | None:
    """Return a file's lines as text, or None if it can't be read as text."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except (OSError, UnicodeDecodeError):
        return None


def relative_asset(path: Path, repo_path: Path) -> str:
    """Repo-relative path, always forward-slashed (matches git's own output)."""
    try:
        return path.relative_to(repo_path).as_posix()
    except ValueError:
        return path.as_posix()
