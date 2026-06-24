from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.discovery.models import ReconciledPlan
from src.executor import reconcile
from src.executor.installer import parse_version, version_satisfies


def test_parse_version_basic() -> None:
    assert parse_version("go1.21.0") == (1, 21, 0)
    assert parse_version("v20.3") == (20, 3)
    assert parse_version("nonsense") == (0,)


def test_version_satisfies_semantic() -> None:
    assert version_satisfies("1.21.0", "1.21.0")
    assert version_satisfies("1.22.0", "1.21.0")
    assert not version_satisfies("1.20.0", "1.21.0")


def test_version_satisfies_match_hint() -> None:
    assert version_satisfies(
        "go version go1.21.5 linux/amd64", "1.21", r"go1\.\d+"
    )


def test_version_satisfies_no_required() -> None:
    assert not version_satisfies("1.21.0", "")


@pytest.mark.asyncio
async def test_reconcile_fast_path_no_deps() -> None:
    plan = await reconcile.reconcile_dependencies(
        AsyncMock(), install_deps=[], toolchain_deps=[],
    )
    assert plan.deps_to_install == []
    assert "No dependencies" in plan.reasoning


@pytest.mark.asyncio
async def test_reconcile_fast_path_apt_only_all_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All apt libs installed → fast-path, LLM not called."""
    monkeypatch.setattr(
        reconcile, "is_apt_package_installed", AsyncMock(return_value=True)
    )
    called: list[bool] = []
    monkeypatch.setattr(
        reconcile,
        "_reconcile_llm",
        lambda *_a, **_kw: (called.append(True), ReconciledPlan(reasoning="", deps_to_install=[]))[1],
    )

    plan = await reconcile.reconcile_dependencies(
        AsyncMock(),
        install_deps=["libssl-dev"],
        toolchain_deps=[],
    )
    assert plan.deps_to_install == []
    assert "already present" in plan.reasoning
    assert not called


@pytest.mark.asyncio
async def test_reconcile_fast_path_version_satisfied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Versioned toolchain at satisfying version → fast-path, LLM not called."""
    monkeypatch.setattr(
        reconcile,
        "detect_installed_version",
        AsyncMock(return_value="go version go1.21.5 linux/amd64"),
    )
    called: list[bool] = []
    monkeypatch.setattr(
        reconcile,
        "_reconcile_llm",
        lambda *_a, **_kw: (called.append(True), ReconciledPlan(reasoning="", deps_to_install=[]))[1],
    )

    plan = await reconcile.reconcile_dependencies(
        AsyncMock(),
        install_deps=[],
        toolchain_deps=[
            {
                "name": "go",
                "version": "1.21.0",
                "install_command": "echo install go",
                "install_method": "binary",
                "verify_command": "go version",
                "version_match_hint": r"go1\.\d+",
            }
        ],
    )
    assert plan.deps_to_install == []
    assert "already present" in plan.reasoning
    assert not called


def test_base_image_packages_includes_preinstalled() -> None:
    for pkg in ("go", "git", "curl", "make", "ca-certificates"):
        assert pkg in reconcile.BASE_IMAGE_PACKAGES
