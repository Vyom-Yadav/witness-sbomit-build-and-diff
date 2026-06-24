from __future__ import annotations

import re

import dagger


def parse_version(version_string: str) -> tuple[int, ...]:
    """Parse a semantic version string into a tuple of integers."""
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version_string)
    if not match:
        return (0,)
    return tuple(int(x) for x in match.groups() if x is not None)


def version_satisfies(installed: str, required: str, match_hint: str | None = None) -> bool:
    """
    Check if installed version satisfies required version using string comparison.

    NOTE: This is for SEMANTIC version toolchains only (Go, Node, Rust, Python, ...).
    Do NOT use it for apt/Debian package versions, which are not semantic
    (epochs, ``~``, ``+dfsg``, ``ubuntu0.1`` suffixes). apt packages are handled by
    presence check only — see ``is_apt_package_installed``.

    Uses fuzzy matching:
    - Exact match: 1.21.0 == 1.21.0
    - Prefix match: go1.21 matches go1.21.0
    - Loose match: 1.21 matches 1.21.0 or 1.21.1
    """
    if not installed or not required:
        return False

    if match_hint:
        installed_match = re.search(match_hint, installed)
        if installed_match:
            installed = installed_match.group(0)

    installed_clean = re.sub(r"[^0-9.]", "", installed)
    required_clean = re.sub(r"[^0-9.]", "", required)

    if installed_clean == required_clean:
        return True

    installed_parts = parse_version(installed_clean)
    required_parts = parse_version(required_clean)

    if not required_parts:
        return True

    # Pad the shorter tuple with zeros so (1,21) is treated as (1,21,0)
    installed_parts = tuple(list(installed_parts) + [0] * (len(required_parts) - len(installed_parts)))
    required_parts = tuple(list(required_parts) + [0] * (len(installed_parts) - len(required_parts)))

    for i, req_part in enumerate(required_parts):
        if i >= len(installed_parts):
            return False
        if installed_parts[i] < req_part:
            return False
        if installed_parts[i] > req_part:
            return True

    return True


async def detect_installed_version(
    container: dagger.Container,
    verify_command: str,
    match_hint: str | None = None,
) -> str | None:
    """
    Detect the installed version of a tool in the container.
    """
    try:
        result = await container.with_exec(["sh", "-c", verify_command]).sync()
        stdout = await result.stdout()
        stderr = await result.stderr()
        output = stdout + stderr

        if not output:
            return None

        if match_hint:
            match = re.search(match_hint, output)
            if match:
                return match.group(0)

        version_patterns = [
            r"(\d+\.\d+\.\d+(?:\.\d+)?)",
            r"v(\d+\.\d+\.\d+)",
            r"(\d+\.\d+)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1) if match.lastindex else match.group(0)

        return output.strip()

    except Exception:
        return None


async def is_apt_package_installed(
    container: dagger.Container,
    package_name: str,
) -> bool:
    """Return True if the apt package is already installed in the container."""
    try:
        result = await container.with_exec(
            ["sh", "-c", f"dpkg -s {package_name} 2>/dev/null | grep -q '^Status: install ok installed'"]
        ).sync()
        await result.stdout()
        return True
    except Exception:
        return False
