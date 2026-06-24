from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

from src.orchestrator.models import (
    HumanOverride,
    PipelineInput,
    PipelineState,
)


@workflow.defn
class SBOMAnalysisWorkflow:
    """Temporal workflow for the SBOM accuracy analysis pipeline.

    Runs all 5 stages sequentially in a single workflow execution.
    Human overrides are received via signals and applied before storage.
    """

    def __init__(self) -> None:
        self._override: HumanOverride | None = None

    @workflow.signal
    def human_override(self, override: HumanOverride) -> None:
        self._override = override

    @workflow.run
    async def run(self, pipeline_input: PipelineInput) -> dict:
        state = PipelineState(
            run_id=pipeline_input.run_id,
        )

        state.discovery_result = await workflow.execute_activity(
            "discover_build_activity",
            args=[state.run_id, pipeline_input.repo_url, pipeline_input.commit_sha],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=5),
        )

        build_instruction = (state.discovery_result or {}).get("build_instruction", {})
        repo_path = (state.discovery_result or {}).get("repo_path", "")

        state.reconciled_plan = await workflow.execute_activity(
            "reconcile_deps_activity",
            args=[state.run_id, build_instruction],
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )

        state.build_result = await workflow.execute_activity(
            "execute_build_activity",
            args=[state.run_id, build_instruction, "A", repo_path, state.reconciled_plan],
            start_to_close_timeout=timedelta(minutes=90),
            retry_policy=RetryPolicy(maximum_attempts=5),
        )

        state.diff_result = await workflow.execute_activity(
            "analyze_diff_activity",
            args=[state.run_id, state.build_result],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=5),
        )

        diff_entries = (state.diff_result or {}).get("entries", [])
        if len(diff_entries) <= 30:
            classification_result = await workflow.execute_activity(
                "classify_diffs_activity",
                args=[state.run_id, diff_entries],
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=RetryPolicy(maximum_attempts=5),
            )
        else:
            classification_result = {
                "classifications": [
                    {
                        "package_name": e.get("package_name", ""),
                        "purl": e.get("purl"),
                        "diff_type": e.get("diff_type"),
                        "sbomit_value": e.get("sbomit_value"),
                        "syft_value": e.get("syft_value"),
                        "classification": "inconclusive",
                        "confidence": 0.0,
                        "reasoning": f"Skipped: too many diffs ({len(diff_entries)} > 30) for AI classification",
                        "evidence_files": [],
                    }
                    for e in diff_entries
                ],
                "metrics": {
                    "total_diffs": len(diff_entries),
                    "classified": {"inconclusive": len(diff_entries)},
                    "avg_confidence": 0.0,
                    "sbomit_accuracy": 0.0,
                    "syft_accuracy": 0.0,
                    "inconclusive_count": len(diff_entries),
                    "human_overridden": 0,
                    "token_usage": 0,
                },
            }
        state.classifications = classification_result["classifications"]
        state.agent_metrics = classification_result["metrics"]

        if self._override:
            state = self._apply_override(state, self._override)

        repo_path = (state.discovery_result or {}).get("repo_path", "")
        await workflow.execute_activity(
            "store_results_activity",
            args=[state.run_id, asdict(state), repo_path],
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(maximum_attempts=5),
        )

        return asdict(state)

    def _apply_override(
        self, state: PipelineState, override: HumanOverride
    ) -> PipelineState:
        if state.classifications:
            for i, cls in enumerate(state.classifications):
                if cls["package_name"] == override.package_name:
                    state.classifications[i]["classification"] = override.new_value
                    state.classifications[i]["confidence"] = 1.0
                    state.classifications[i]["reasoning"] = (
                        f"[OVERRIDDEN by {override.human_id}] {override.reason}"
                    )
                    state.classifications[i]["human_overridden"] = True
                    break

            state.override_history.append({
                "package": override.package_name,
                "original": override.original_value,
                "override": override.new_value,
                "reason": override.reason,
                "human_id": override.human_id,
                "timestamp": override.timestamp,
            })

        return state
