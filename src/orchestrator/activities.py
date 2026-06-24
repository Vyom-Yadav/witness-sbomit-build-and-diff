from __future__ import annotations

from typing import Any

from temporalio import activity

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openrouter import ChatOpenRouter

from src.analyzer.differ import diff_sboms, diff_to_dicts
from src.analyzer.parser import parse_spdx_json
from src.classifier.graph import classify_diffs as classify_diffs_fn
from src.config import settings
from src.discovery.graph import discover_build as discover_build_fn
from src.executor.runner import run_build as run_build_fn
from src.storage import (
    create_run,
    save_agent_metrics,
    save_build_artifact,
    save_build_instruction,
    save_classification,
    save_diffs,
    save_reconciled_plan,
    update_run_status,
)
from src.discovery.extract_models import (
    ExtractedBuildCommand,
    ExtractedDependencies,
    ExtractedOutputPath,
    ExtractedSBOMStrategy,
    ConfidenceScore,
    ReconciledDepsList,
)
from src.discovery.models import ReconciledDep
from src.discovery.prompts import (
    BUILD_COMMAND_PROMPT,
    CONFIDENCE_EXTRACTION_PROMPT,
    DEPENDENCIES_PROMPT,
    OUTPUT_PATH_PROMPT,
    SBOM_STRATEGY_PROMPT,
    RECONCILE_DEPS_PROMPT,
    RECONCILE_REASONING_PROMPT,
)
from src.executor.reconcile import BASE_IMAGE_PACKAGES
from src.storage.models import RunStatus

@activity.defn
async def create_run_activity(
    repo_url: str,
    commit_sha: str | None,
) -> str:
    """Create a new run in the database and return the run ID."""
    run_id = create_run(repo_url, commit_sha)
    return run_id

@activity.defn
async def discover_build_activity(
    run_id: str,
    repo_url: str,
    commit_sha: str | None,
) -> dict:
    """Clone repo, then run the discovery agent to find build command."""
    import subprocess
    from pathlib import Path
    update_run_status(run_id, RunStatus.DISCOVERING)
    activity.heartbeat("Cloning repository...")
    repo_path = Path("/tmp/sbomit_repo") / run_id
    # Ensure parent directory exists
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    # Remove existing directory if present (from previous failed attempts)
    if repo_path.exists():
        import shutil
        shutil.rmtree(repo_path)
    clone_cmd = ["git", "clone", "--depth=1", repo_url, str(repo_path)]
    # Run git without any user config (ignore SSH rewrite, credentials, etc.)
    import os
    env = os.environ.copy()
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    try:
        result = subprocess.run(clone_cmd, check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as e:
        activity.logger.error(f"Git clone failed with exit code {e.returncode}")
        activity.logger.error(f"Command: {e.cmd}")
        activity.logger.error(f"Stdout: {e.stdout}")
        activity.logger.error(f"Stderr: {e.stderr}")
        raise
    if commit_sha:
        checkout_cmd = ["git", "-C", str(repo_path), "checkout", commit_sha]
        try:
            subprocess.run(
                checkout_cmd, check=True, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            activity.logger.error(f"Git checkout failed with exit code {e.returncode}")
            activity.logger.error(f"Command: {e.cmd}")
            activity.logger.error(f"Stdout: {e.stdout}")
            activity.logger.error(f"Stderr: {e.stderr}")
            raise
    activity.heartbeat("Running discovery agent...")
    result = await discover_build_fn(repo_url, commit_sha, str(repo_path))
    result["repo_path"] = str(repo_path)
    activity.heartbeat("Discovery complete — analysis_text produced")
    # No longer saves build_instruction/sbom_strategy here — extraction
    # activities produce those fields and the workflow assembles them.
    return result

@activity.defn
async def reconcile_deps_activity(
    run_id: str,
    build_instruction: dict,
) -> dict:
    """Probe the build container and return probe results.
    Only probes — does NOT call the LLM. The LLM reasoning and extraction
    are separate activities so each step's input/output is recorded.
    """
    from pathlib import Path
    from src.executor.reconcile import probe_container_and_check
    update_run_status(run_id, RunStatus.RECONCILING)
    activity.heartbeat("Probing container for dependency reconciliation...")
    install_deps = build_instruction.get("install_deps", [])
    toolchain_deps = build_instruction.get("toolchain_deps", [])
    if not install_deps and not toolchain_deps:
        return {
            "probe_results": [],
            "requested_deps": {},
            "all_satisfied": True,
            "reasoning": "No dependencies requested.",
            "deps_to_install": [],
        }
    import dagger
    log_path = Path("/tmp") / f"reconcile_{run_id}.log"
    with open(str(log_path), "a") as log_file:
        async with dagger.Connection(dagger.Config(log_output=log_file)) as client:
            image_tar = client.host().file("/tmp/sbomit-base.tar")
            container = client.container().import_(image_tar)
            result = await probe_container_and_check(
                container, install_deps, toolchain_deps,
            )
    activity.heartbeat(
        f"Probe complete: {len(result['probe_results'])} deps checked"
    )
    return result

@activity.defn
async def execute_build_activity(
    run_id: str,
    build_instruction: dict,
    witness_label: str,
    repo_path: str,
    reconciled_plan: dict | None = None,
) -> dict:
    """Execute a build with witness, using the pre-cloned repo."""
    update_run_status(run_id, RunStatus.BUILDING)
    activity.heartbeat("Starting build...")
    from src.storage import get_run
    run_data = get_run(run_id)
    if not run_data:
        raise ValueError(f"Run {run_id} not found in database")
    repo_url = run_data["repo_url"]
    commit_sha = run_data.get("commit_sha")
    result = await run_build_fn(
        repo_url=repo_url,
        commit_sha=commit_sha,
        build_instruction=build_instruction,
        witness_label=witness_label,
        base_image=settings.build_base_image,
        repo_path=repo_path,
        run_id=run_id,
        reconciled_plan=reconciled_plan,
    )
    activity.heartbeat("Build complete, saving artifacts...")
    for artifact_type in [
        "binary", "attestation", "sbom_syft", "sbom_sbomit",
        "witness_log", "syft_log", "sbomit_log", "dagger_log",
    ]:
        key = f"{artifact_type}_path"
        if result.get(key):
            save_build_artifact(
                run_id,
                witness_label,
                artifact_type,
                result[key],
            )
    return result

@activity.defn
async def analyze_diff_activity(
    run_id: str,
    build_result: dict,
    sbom_reference_path: str | None = None,
) -> dict:
    """Parse SBOMs and compute deterministic diff."""
    update_run_status(run_id, RunStatus.ANALYZING)
    # Use sbomit SBOM from build result
    sbomit_path = build_result.get("sbom_sbomit_path", "")
    # Use syft SBOM from build result or reference path
    syft_path = build_result.get("sbom_syft_path", "")
    if not syft_path and sbom_reference_path:
        syft_path = sbom_reference_path
    sbomit_pkgs = parse_spdx_json(sbomit_path) if sbomit_path else []
    syft_pkgs = parse_spdx_json(syft_path) if syft_path else []
    diff = diff_sboms(sbomit_pkgs, syft_pkgs)
    diff_dicts = diff_to_dicts(diff)
    save_diffs(run_id, diff_dicts)
    return {
        "entries": diff_dicts,
        "summary": {
            "total_sbomit": diff.total_sbomit,
            "total_syft": diff.total_syft,
            "hash_matched": diff.hash_matched,
            "purl_matched": diff.purl_matched,
            "similarity_score": diff.similarity_score,
            "total_diffs": len(diff.entries),
        },
    }

@activity.defn
async def classify_diffs_activity(
    run_id: str,
    diff_entries: list[dict],
) -> dict:
    """Run agent-based classification on each diff entry."""
    import tempfile
    from pathlib import Path
    update_run_status(run_id, RunStatus.CLASSIFYING)
    activity.heartbeat(f"Classifying {len(diff_entries)} diffs...")
    context_path = Path(tempfile.gettempdir()) / f"classifier_context_{run_id[:8]}.json"
    result = await classify_diffs_fn(diff_entries, str(context_path))
    for cls in result["classifications"]:
        save_classification(
            run_id,
            diff_id="",
            classification=cls["classification"],
            confidence=cls["confidence"],
            reasoning=cls["reasoning"],
            evidence_files=cls.get("evidence_files", []),
        )
    save_agent_metrics(run_id, result["metrics"])
    return result

@activity.defn
async def store_results_activity(run_id: str, _state: dict, repo_path: str) -> None:
    """Final storage step — update run status, save assembled results, clean up."""
    import shutil
    from pathlib import Path
    update_run_status(run_id, RunStatus.COMPLETE)
    discovery = _state.get("discovery_result") or {}
    if discovery.get("build_instruction"):
        save_build_instruction(
            run_id,
            discovery["build_instruction"],
            discovery.get("sbom_strategy", {}),
            discovery.get("confidence_score", 0.0),
        )
    shutil.rmtree(Path(repo_path), ignore_errors=True)

# ---------------------------------------------------------------------------
# Field-by-field extraction activities — each is a single LLM call with
# recorded input/output in Temporal's event history.
# ---------------------------------------------------------------------------

@activity.defn
async def extract_build_command_activity(
    run_id: str,
    analysis_text: str,
) -> dict:
    """Extract build command (executable, arguments, env_vars) from analysis text."""
    activity.heartbeat(f"Extracting build command: {analysis_text[:200]}...")
    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    llm_structured = llm.with_structured_output(ExtractedBuildCommand)
    # Simple extraction — just the analysis text
    messages = [
        SystemMessage(
            content=BUILD_COMMAND_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
        ),
    ]
    try:
        result = llm_structured.invoke(messages)
    except Exception:
        activity.logger.error("Build command extraction LLM call failed")
        return {"executable": "", "arguments": [], "env_vars": {}}
    if isinstance(result, ExtractedBuildCommand):
        return {"executable": result.executable, "arguments": result.arguments, "env_vars": result.env_vars}
    if isinstance(result, dict):
        return result
    return {"executable": "", "arguments": [], "env_vars": {}}

@activity.defn
async def extract_dependencies_activity(
    run_id: str,
    analysis_text: str,
    build_command_json: str,
) -> dict:
    """Extract dependencies (install_deps + toolchain_deps) from analysis text and build command."""
    activity.heartbeat("Extracting dependencies from analysis...")
    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    llm_structured = llm.with_structured_output(ExtractedDependencies)

    messages = [
        SystemMessage(
            content=DEPENDENCIES_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
            + "\n\n=== EXTRACTED BUILD COMMAND ===\n"
            + build_command_json
        ),
    ]
    try:
        result: Any = llm_structured.invoke(messages)
    except Exception:
        activity.logger.error("Dependency extraction LLM call failed")
        return {"install_deps": [], "toolchain_deps": []}
    if isinstance(result, ExtractedDependencies):
        return {
            "install_deps": result.install_deps,
            "toolchain_deps": [t.model_dump() for t in result.toolchain_deps],
        }
    if isinstance(result, dict):
        return result
    return {"install_deps": [], "toolchain_deps": []}

@activity.defn
async def extract_sbom_strategy_activity(
    run_id: str,
    analysis_text: str,
    build_command_json: str,
) -> dict:
    """Extract SBOM scanning strategy from analysis text and build command."""
    activity.heartbeat("Extracting SBOM strategy from analysis...")
    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    llm_structured = llm.with_structured_output(ExtractedSBOMStrategy)

    messages = [
        SystemMessage(
            content=SBOM_STRATEGY_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
            + "\n\n=== EXTRACTED BUILD COMMAND ===\n"
            + build_command_json
        ),
    ]
    try:
        result = llm_structured.invoke(messages)
    except Exception:
        activity.logger.error("SBOM strategy extraction LLM call failed")
        return {"inferred_target": "source", "syft_target_path": "dir:.", "reasoning": "Extraction failed"}
    if isinstance(result, ExtractedSBOMStrategy):
        return result.model_dump()
    if isinstance(result, dict):
        return result
    return {"inferred_target": "source", "syft_target_path": "dir:.", "reasoning": "Extraction failed"}

@activity.defn
async def extract_output_path_activity(
    run_id: str,
    analysis_text: str,
    build_command_json: str,
) -> dict:
    """Extract build output path from analysis text and build command."""
    activity.heartbeat("Extracting output path from analysis...")
    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    llm_structured = llm.with_structured_output(ExtractedOutputPath)

    messages = [
        SystemMessage(
            content=OUTPUT_PATH_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
            + "\n\n=== EXTRACTED BUILD COMMAND ===\n"
            + build_command_json
        ),
    ]
    try:
        result = llm_structured.invoke(messages)
    except Exception:
        activity.logger.error("Output path extraction LLM call failed")
        return {"output_path": ".", "reasoning": "Extraction failed"}
    if isinstance(result, ExtractedOutputPath):
        return {"output_path": result.output_path, "reasoning": result.reasoning}
    if isinstance(result, dict):
        return result
    return {"output_path": ".", "reasoning": "Extraction failed"}

@activity.defn
async def extract_confidence_activity(
    run_id: str,
    analysis_text: str,
) -> float:
    """Extract confidence score from analysis text."""
    activity.heartbeat("Extracting confidence from analysis...")
    llm = ChatOpenRouter(
        model=settings.openrouter_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    llm_structured = llm.with_structured_output(ConfidenceScore)

    messages = [
        SystemMessage(
            content=CONFIDENCE_EXTRACTION_PROMPT
            + "\n\n=== ANALYSIS ===\n"
            + analysis_text
        ),
    ]
    try:
        result = llm_structured.invoke(messages)
    except Exception:
        activity.logger.error("Confidence extraction LLM call failed")
        return 0.0
    if isinstance(result, ConfidenceScore):
        return result.confidence
    if isinstance(result, dict):
        return float(result.get("confidence", 0.0))
    return 0.0

# ---------------------------------------------------------------------------
# Reconcile activities — probe (deterministic) + reasoning + extraction
# ---------------------------------------------------------------------------

@activity.defn
async def reconcile_reasoning_activity(
    run_id: str,
    probe_results_json: str,
    requested_deps_json: str,
) -> str:
    """LLM reasoning step — produce free-text reasoning about deps to install."""
    import json

    activity.heartbeat("Reasoning about dependency reconciliation...")
    llm = ChatOpenRouter(
        model=settings.classifier_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    reasoning_system = RECONCILE_REASONING_PROMPT.format(
        base_image_packages=", ".join(BASE_IMAGE_PACKAGES),
    )
    probe_results = json.loads(probe_results_json)
    requested = json.loads(requested_deps_json)
    response = llm.invoke([
        SystemMessage(content=reasoning_system),
        HumanMessage(content=(
            "REQUESTED:\n"
            + json.dumps(requested, indent=2)
            + "\n\nPROBE RESULTS (ground truth from the live container):\n"
            + json.dumps(probe_results, indent=2)
        )),
    ])
    reasoning_text = (
        response.content
        if hasattr(response, "content") and isinstance(response.content, str)
        else str(response)
    )
    activity.heartbeat(f"Reasoning complete: {reasoning_text[:200]}...")
    return reasoning_text

@activity.defn
async def reconcile_extract_deps_activity(
    run_id: str,
    reasoning_text: str,
    probe_results_json: str,
) -> dict:
    """LLM extraction step — produce structured deps list from reasoning text."""
    import json

    activity.heartbeat("Extracting deps list from reasoning...")
    llm = ChatOpenRouter(
        model=settings.classifier_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    deps_llm = llm.with_structured_output(ReconciledDepsList)
    probe_results = json.loads(probe_results_json)
    result = deps_llm.invoke([
        SystemMessage(content=RECONCILE_DEPS_PROMPT),
        HumanMessage(content=(
            "REASONING:\n"
            + reasoning_text
            + "\n\nPROBE RESULTS (ground truth from the live container):\n"
            + json.dumps(probe_results, indent=2)
        )),
    ])
    if isinstance(result, ReconciledDepsList):
        deps = [d.model_dump() for d in result.deps_to_install]
    elif isinstance(result, dict):
        deps_raw = result.get("deps_to_install", [])
        deps = [ReconciledDep(**d).model_dump() if isinstance(d, dict) else d for d in deps_raw]
    else:
        deps = []
    activity.heartbeat(f"Extraction complete: {len(deps)} deps to install")
    return {"deps_to_install": deps, "reasoning_text": reasoning_text}
