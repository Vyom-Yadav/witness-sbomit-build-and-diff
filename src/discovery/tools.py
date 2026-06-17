import re
from pathlib import Path

IGNORED_DIRS = {".git", "node_modules", "vendor", "third_party", "tests", "__pycache__", ".venv"}

def list_directory(path: str, max_depth: int = 3) -> str:
    """List directory structure as a flat list of paths, ignoring noise."""
    target = Path(path)
    if not target.exists():
        return f"Error: path '{path}' does not exist"
    if not target.is_dir():
        return f"Error: '{path}' is not a directory"

    paths: list[str] = []

    def _walk_flat(current_path: Path, current_depth: int):
        if current_depth > max_depth:
            return
        try:
            for entry in current_path.iterdir():
                if entry.name in IGNORED_DIRS or entry.name.startswith("."):
                    continue

                rel_path = entry.relative_to(target).as_posix()
                if entry.is_dir():
                    _walk_flat(entry, current_depth + 1)
                else:
                    paths.append(rel_path)
        except (PermissionError, OSError):
            pass

    _walk_flat(target, 1)
    return "\n".join(sorted(paths)) if paths else "Empty directory"

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
        return f"Error: file has {line_count} lines (max 1000). Use grep_file instead."
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
