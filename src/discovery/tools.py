from __future__ import annotations

import re
from pathlib import Path

IGNORED_DIRS = {".git", "node_modules", "vendor", "third_party", "tests", "__pycache__", ".venv"}


def list_directory(path: str, max_depth: int = 2) -> str:
    """List directory structure, ignoring noise directories."""
    target = Path(path)
    if not target.exists():
        return f"Error: path '{path}' does not exist"
    if not target.is_dir():
        return f"Error: '{path}' is not a directory"

    lines: list[str] = []
    _walk(target, lines, depth=0, max_depth=max_depth, prefix="")
    return "\n".join(lines) if lines else "Empty directory"


def _walk(
    path: Path, lines: list[str], depth: int, max_depth: int, prefix: str
) -> None:
    if depth > max_depth:
        return
    try:
        entries = sorted(path.iterdir(), key=lambda e: (not e.is_dir(), e.name))
    except (PermissionError, OSError):
        return

    for entry in entries:
        if entry.name in IGNORED_DIRS or entry.name.startswith("."):
            continue
        connector = "├── " if entry != entries[-1] else "└── "
        lines.append(f"{prefix}{connector}{entry.name}{'/' if entry.is_dir() else ''}")
        if entry.is_dir():
            extension = "│   " if entry != entries[-1] else "    "
            _walk(entry, lines, depth + 1, max_depth, prefix + extension)


def read_file_content(filepath: str) -> str:
    """Read file content, rejecting files over 1000 lines."""
    target = Path(filepath)
    if not target.exists():
        return f"Error: file '{filepath}' does not exist"
    if not target.is_file():
        return f"Error: '{filepath}' is not a file"

    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"Error reading file: {e}"

    line_count = text.count("\n") + 1
    if line_count > 1000:
        return f"Error: file has {line_count} lines (max 1000). Use read_file_grep instead."
    return text


def read_file_grep(filepath: str, regex: str) -> str:
    """Search file for regex matches with 2 lines of context."""
    target = Path(filepath)
    if not target.exists():
        return f"Error: file '{filepath}' does not exist"

    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        return f"Error reading file: {e}"

    try:
        pattern = re.compile(regex, re.IGNORECASE)
    except re.error as e:
        return f"Error: invalid regex '{regex}': {e}"

    matches: list[str] = []
    matched_indices: set[int] = set()

    for i, line in enumerate(lines):
        if pattern.search(line):
            for j in range(max(0, i - 2), min(len(lines), i + 3)):
                matched_indices.add(j)

    for i in sorted(matched_indices):
        marker = ">>>" if pattern.search(lines[i]) else "   "
        matches.append(f"{i + 1:4d} {marker} {lines[i]}")

    return "\n".join(matches) if matches else f"No matches for '{regex}' in {filepath}"
