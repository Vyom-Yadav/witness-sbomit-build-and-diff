from __future__ import annotations

import json
from typing import Any

import dagger
from temporalio import activity

from src.config import settings
from src.discovery.models import ReconciledDep, ReconciledPlan, ToolchainDependency
from src.discovery.extract_models import ReconciledDepsList
from src.discovery.prompts import (
    RECONCILE_DEPS_PROMPT,
    RECONCILE_REASONING_PROMPT,
)
from src.executor.installer import (
    detect_installed_version,
    is_apt_package_installed,
    version_satisfies,
)


def _heartbeat(message: str) -> None:
    """Emit a Temporal heartbeat if running inside an activity; no-op otherwise."""
    try:
        activity.heartbeat(message)
    except RuntimeError:
        pass

# Packages the base image (docker/Dockerfile.base) ships. Kept here so the reconciler
# knows what is preinstalled without probing for everything. Must stay in sync with the
# Dockerfile.
BASE_IMAGE_PACKAGES: list[str] = [
    "go",
    "git",
    "curl",
    "wget",
    "build-essential",
    "gcc",
    "g++",
    "make",
    "cmake",
    "pkg-config",
    "autoconf",
    "automake",
    "libtool",
    "ca-certificates",
]


async def _probe_toolchain(
    container: dagger.Container,
    dep: ToolchainDependency,
) -> dict[str, Any]:
    """Probe the live container for a structured toolchain dependency."""
    if dep.install_method == "apt":
        installed = await is_apt_package_installed(container, dep.name)
        return {
            "name": dep.name,
            "kind": "apt",
            "installed": installed,
            "detected_version": None,
            "required_version": dep.version,
            "satisfied": installed,  # apt: presence-only, no semver
        }

    version = await detect_installed_version(
        container, dep.verify_command, dep.version_match_hint
    )
    satisfied = (
        version is not None
        and dep.version is not None
        and version_satisfies(version, dep.version, dep.version_match_hint)
    )
    return {
        "name": dep.name,
        "kind": dep.install_method,
        "installed": version is not None,
        "detected_version": version,
        "required_version": dep.version,
        "satisfied": satisfied,
    }


async def _probe_apt_lib(
    container: dagger.Container,
    package: str,
) -> dict[str, Any]:
    """Probe the live container for a raw apt system library."""
    installed = await is_apt_package_installed(container, package)
    return {
        "name": package,
        "kind": "apt",
        "installed": installed,
        "detected_version": None,
        "required_version": None,
        "satisfied": installed,  # apt: presence-only
    }


def _reconcile_llm(
    requested: dict[str, Any],
    probe_results: list[dict[str, Any]],
) -> ReconciledPlan:
    """Two-step LLM reconciliation: reason first, then extract deps list."""
    from langchain_openrouter import ChatOpenRouter

    llm = ChatOpenRouter(
        model=settings.classifier_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )

    probe_json = json.dumps(probe_results, indent=2)
    requested_json = json.dumps(requested, indent=2)

    # ---- Step 1: Reasoning (free text, no schema) ----
    reasoning_system = RECONCILE_REASONING_PROMPT.format(
        base_image_packages=", ".join(BASE_IMAGE_PACKAGES),
    )
    from langchain_core.messages import HumanMessage, SystemMessage

    reasoning_response = llm.invoke([
        SystemMessage(content=reasoning_system),
        HumanMessage(content=(
            "REQUESTED:\n"
            + requested_json
            + "\n\nPROBE RESULTS (ground truth from the live container):\n"
            + probe_json
        )),
    ])
    reasoning_text = (
        reasoning_response.content
        if hasattr(reasoning_response, "content") and isinstance(reasoning_response.content, str)
        else str(reasoning_response)
    )

    # ---- Step 2: Deps extraction (structured) ----
    deps_llm = llm.with_structured_output(ReconciledDepsList)

    result: Any = deps_llm.invoke([
        SystemMessage(content=RECONCILE_DEPS_PROMPT),
        HumanMessage(content=(
            "REASONING:\n"
            + reasoning_text
            + "\n\nPROBE RESULTS (ground truth from the live container):\n"
            + probe_json
        )),
    ])

    if isinstance(result, ReconciledDepsList):
        deps = result.deps_to_install
    elif isinstance(result, dict):
        deps_raw = result.get("deps_to_install", [])
        deps = [ReconciledDep(**d) if isinstance(d, dict) else d for d in deps_raw]
    else:
        deps = []
    return ReconciledPlan(reasoning=reasoning_text, deps_to_install=deps)


async def reconcile_dependencies(
    container: dagger.Container,
    install_deps: list[str],
    toolchain_deps: list[dict[str, Any]],
) -> ReconciledPlan:
    """Probe the live container, then ask an LLM for the minimal set of installs.

    This merges the previously mutually-exclusive ``install_deps`` (apt libs) and
    ``toolchain_deps`` (structured toolchains) paths into a single reconciled plan,
    so a build needing both a language toolchain AND system libs is handled correctly.
    """
    _heartbeat("Probing container for already-installed dependencies...")

    toolchain_models = [ToolchainDependency(**d) for d in toolchain_deps]

    probe_results: list[dict[str, Any]] = []
    for dep in toolchain_models:
        probe_results.append(await _probe_toolchain(container, dep))
    for lib in install_deps:
        probe_results.append(await _probe_apt_lib(container, lib))

    # Fast path: nothing requested at all.
    if not probe_results:
        return ReconciledPlan(reasoning="No dependencies requested.", deps_to_install=[])

    # Fast path: every requested dep is already satisfied -> skip the LLM entirely.
    if all(p.get("satisfied", p["installed"]) for p in probe_results):
        return ReconciledPlan(
            reasoning="All requested dependencies already present in the container.",
            deps_to_install=[],
        )

    requested = {
        "install_deps": install_deps,
        "toolchain_deps": [m.model_dump() for m in toolchain_models],
    }

    _heartbeat("Reconciling dependencies via LLM...")
    return _reconcile_llm(requested, probe_results)


# ---------------------------------------------------------------------------
# Standalone functions for Temporal activities — each LLM step is a separate
# activity with recorded input/output.
# ---------------------------------------------------------------------------


async def probe_container_and_check(
    container: dagger.Container,
    install_deps: list[str],
    toolchain_deps: list[dict[str, Any]],
) -> dict:
    """Probe the live container for dependencies and return probe results.

    Does NOT call the LLM. Returns probe results + fast-path flags so the
    workflow can decide whether to invoke the reasoning activity.
    """
    toolchain_models = [ToolchainDependency(**d) for d in toolchain_deps]

    probe_results: list[dict[str, Any]] = []
    for dep in toolchain_models:
        probe_results.append(await _probe_toolchain(container, dep))
    for lib in install_deps:
        probe_results.append(await _probe_apt_lib(container, lib))

    if not probe_results:
        return {
            "probe_results": [],
            "requested_deps": {"install_deps": install_deps, "toolchain_deps": toolchain_deps},
            "all_satisfied": True,
        }

    all_satisfied = all(p.get("satisfied", p["installed"]) for p in probe_results)
    requested = {
        "install_deps": install_deps,
        "toolchain_deps": [m.model_dump() for m in toolchain_models],
    }

    return {
        "probe_results": probe_results,
        "requested_deps": requested,
        "all_satisfied": all_satisfied,
    }


def reconcile_reasoning_fn(
    requested: dict[str, Any],
    probe_results: list[dict[str, Any]],
) -> str:
    """LLM reasoning step — produces free-text reasoning about which deps to install.

    Standalone so it can be wrapped in a Temporal activity.
    """
    import json

    from langchain_openrouter import ChatOpenRouter

    llm = ChatOpenRouter(
        model=settings.classifier_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )

    reasoning_system = RECONCILE_REASONING_PROMPT.format(
        base_image_packages=", ".join(BASE_IMAGE_PACKAGES),
    )
    from langchain_core.messages import HumanMessage, SystemMessage

    probe_json = json.dumps(probe_results, indent=2)
    requested_json = json.dumps(requested, indent=2)

    response = llm.invoke([
        SystemMessage(content=reasoning_system),
        HumanMessage(content=(
            "REQUESTED:\n"
            + requested_json
            + "\n\nPROBE RESULTS (ground truth from the live container):\n"
            + probe_json
        )),
    ])
    return response.content if hasattr(response, "content") and isinstance(response.content, str) else str(response)


def extract_deps_fn(
    reasoning_text: str,
    probe_results: list[dict[str, Any]],
) -> ReconciledPlan:
    """LLM extraction step — produces the structured deps list from reasoning text.

    Standalone so it can be wrapped in a Temporal activity.
    """
    import json

    from langchain_openrouter import ChatOpenRouter

    llm = ChatOpenRouter(
        model=settings.classifier_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    deps_llm = llm.with_structured_output(ReconciledDepsList)

    from langchain_core.messages import HumanMessage, SystemMessage

    probe_json = json.dumps(probe_results, indent=2)

    result = deps_llm.invoke([
        SystemMessage(content=RECONCILE_DEPS_PROMPT),
        HumanMessage(content=(
            "REASONING:\n"
            + reasoning_text
            + "\n\nPROBE RESULTS (ground truth from the live container):\n"
            + probe_json
        )),
    ])

    if isinstance(result, ReconciledDepsList):
        return ReconciledPlan(reasoning=reasoning_text, deps_to_install=result.deps_to_install)
    if isinstance(result, dict):
        deps_raw = result.get("deps_to_install", [])
        deps = [ReconciledDep(**d) if isinstance(d, dict) else d for d in deps_raw]
        return ReconciledPlan(reasoning=reasoning_text, deps_to_install=deps)
    return ReconciledPlan(reasoning=reasoning_text, deps_to_install=[])
