import fnmatch
import re
from pathlib import Path

IGNORED_DIRS = {".git", "node_modules", "vendor", "third_party", "tests", "__pycache__", ".venv"}

# Categorized allowlist of files that carry build-command, env-var, and dependency
# signals. Patterns are matched case-insensitively against the file's basename,
# except CI patterns which match the POSIX-relative path. Ordered by signal quality:
# CI and BUILD/MANIFEST files are primary sources; DOCS are fallback (prose, grep-only).
KNOWN_BUILD_FILES: dict[str, list[str]] = {
    "CI": [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
    ],
    "BUILD": [
        "Makefile",
        "GNUmakefile",
        "Taskfile.yml",
        "Taskfile.yaml",
        "Justfile",
        "justfile",
        "magefile.go",
        "build.sh",
    ],
    "MANIFEST": [
        "go.mod",
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        ".tool-versions",
    ],
    "CONTAINER": [
        "Dockerfile",
        "Dockerfile.*",
        "*.Dockerfile",
    ],
    "DOCS": [
        "README*",
        "INSTALL*",
        "CONTRIBUTING*",
        "DEVELOPING*",
        "DEVELOPMENT*",
        "BUILDING*",
        "HACKING*",
    ],
}

# CI patterns are matched against the relative path, not just the basename.
_PATH_MATCH_CATEGORIES = {"CI"}


def _categorize(rel_path: str, basename: str) -> str | None:
    """Return the signal category for a file, or None if it is not a known build file."""
    for category, patterns in KNOWN_BUILD_FILES.items():
        target = rel_path if category in _PATH_MATCH_CATEGORIES else basename
        for pattern in patterns:
            if fnmatch.fnmatch(target.lower(), pattern.lower()):
                return category
    return None


def build_signal_manifest(path: str, max_depth: int = 4) -> str:
    """Produce a compact, categorized manifest of build-signal files in the repo.

    Returns ONLY file paths and line counts (never file contents), so it stays tiny
    regardless of repo size. The discovery agent uses this map to decide which files
    to inspect with grep_file/read_file.
    """
    target = Path(path)
    if not target.exists():
        return f"Error: path '{path}' does not exist"
    if not target.is_dir():
        return f"Error: '{path}' is not a directory"

    found: dict[str, list[str]] = {category: [] for category in KNOWN_BUILD_FILES}

    def _walk(current_path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            entries = list(current_path.iterdir())
        except (PermissionError, OSError):
            return
        for entry in entries:
            # Allow .github/.circleci/.gitlab even though they start with '.'
            if entry.is_dir():
                if entry.name in IGNORED_DIRS:
                    continue
                if entry.name.startswith(".") and entry.name not in {".github", ".circleci"}:
                    continue
                _walk(entry, depth + 1)
                continue

            rel_path = entry.relative_to(target).as_posix()
            category = _categorize(rel_path, entry.name)
            if category is None:
                continue
            try:
                line_count = entry.read_text(encoding="utf-8", errors="replace").count("\n") + 1
            except Exception:
                line_count = 0
            found[category].append(f"{rel_path} ({line_count} lines)")

    _walk(target, 1)

    lines: list[str] = []
    for category, patterns in KNOWN_BUILD_FILES.items():
        files = sorted(found[category])
        if files:
            lines.append(f"{category}: {', '.join(files)}")

    if not lines:
        return "No known build-signal files found in the repository."
    return "\n".join(lines)

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
