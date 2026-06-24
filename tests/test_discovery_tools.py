from __future__ import annotations

from pathlib import Path

from src.discovery.tools import build_signal_manifest


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "Makefile").write_text("build:\n\tgo build -o bin/app .\n")
    (tmp_path / "go.mod").write_text("module example.com/app\n\ngo 1.21\n")
    (tmp_path / "README.md").write_text("# App\nRun make build\n")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "release.yml").write_text("jobs:\n  build:\n    steps: []\n")
    # Noise that must be ignored
    (tmp_path / "main.go").write_text("package main\n")
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "package.json").write_text("{}\n")
    return tmp_path


def test_manifest_categorizes_known_files(tmp_path: Path) -> None:
    manifest = build_signal_manifest(str(_make_repo(tmp_path)))

    assert "BUILD: Makefile" in manifest
    assert "MANIFEST: go.mod" in manifest
    assert "DOCS: README.md" in manifest
    assert ".github/workflows/release.yml" in manifest
    assert "CI:" in manifest


def test_manifest_includes_line_counts(tmp_path: Path) -> None:
    manifest = build_signal_manifest(str(_make_repo(tmp_path)))
    # go.mod has 3 lines of content + trailing newline -> 4 via count("\n")+1
    assert "go.mod (" in manifest
    assert "lines)" in manifest


def test_manifest_ignores_noise_dirs(tmp_path: Path) -> None:
    manifest = build_signal_manifest(str(_make_repo(tmp_path)))
    # package.json inside node_modules must not appear
    assert "node_modules" not in manifest
    # raw source files are not build signals
    assert "main.go" not in manifest


def test_manifest_no_contents_leaked(tmp_path: Path) -> None:
    manifest = build_signal_manifest(str(_make_repo(tmp_path)))
    # Must be paths + counts only, never file bodies
    assert "go build" not in manifest
    assert "package main" not in manifest


def test_manifest_empty_repo(tmp_path: Path) -> None:
    manifest = build_signal_manifest(str(tmp_path))
    assert manifest == "No known build-signal files found in the repository."


def test_manifest_missing_path() -> None:
    assert "does not exist" in build_signal_manifest("/nonexistent/path/xyz")
