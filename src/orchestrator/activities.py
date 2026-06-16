from __future__ import annotations

from temporalio import activity

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
    update_run_status,
)
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
    repo_path.mkdir(parents=True, exist_ok=True)

    clone_cmd = ["git", "clone", "--depth=1", repo_url, str(repo_path)]
    subprocess.run(clone_cmd, check=True, capture_output=True, text=True)

    if commit_sha:
        subprocess.run(
            ["git", "-C", str(repo_path), "checkout", commit_sha],
            check=True, capture_output=True, text=True,
        )

    activity.heartbeat("Running discovery agent...")
    result = await discover_build_fn(repo_url, commit_sha, str(repo_path))

    result["repo_path"] = str(repo_path)
    activity.heartbeat("Discovery complete")

    save_build_instruction(
        run_id,
        result["build_instruction"],
        result["sbom_strategy"],
        result["confidence_score"],
    )
    return result


@activity.defn
async def execute_build_activity(
    run_id: str,
    build_instruction: dict,
    witness_label: str,
    repo_path: str,
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
    """Final storage step — update run status to complete and clean up."""
    import shutil
    from pathlib import Path

    update_run_status(run_id, RunStatus.COMPLETE)
    shutil.rmtree(Path(repo_path), ignore_errors=True)
