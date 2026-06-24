from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class PipelineStep(StrEnum):
    DISCOVER = "discover"
    RECONCILE = "reconcile"
    EXECUTE = "execute"
    ANALYZE_DIFF = "analyze_diff"
    CLASSIFY = "classify"
    STORE = "store"
    COMPLETE = "complete"


@dataclass
class PipelineState:
    run_id: str = ""
    discovery_result: dict | None = None
    reconciled_plan: dict | None = None
    build_result: dict | None = None
    diff_result: dict | None = None
    classifications: list[dict] | None = None
    agent_metrics: dict | None = None
    human_overrides: dict = field(default_factory=dict)
    override_history: list[dict] = field(default_factory=list)


@dataclass
class PipelineInput:
    repo_url: str
    commit_sha: str | None = None
    run_id: str = ""


@dataclass
class HumanOverride:
    step: PipelineStep
    package_name: str
    override_field: str
    original_value: str
    new_value: str
    reason: str
    human_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )


# ---------------------------------------------------------------------------
# Activity input models — typed so Temporal can serialize them into event history
# ---------------------------------------------------------------------------


@dataclass
class BuildCommandExtractionInput:
    run_id: str
    analysis_text: str


@dataclass
class DependencyExtractionInput:
    run_id: str
    analysis_text: str
    build_command_json: str


@dataclass
class SBOMStrategyExtractionInput:
    run_id: str
    analysis_text: str
    build_command_json: str


@dataclass
class OutputPathExtractionInput:
    run_id: str
    analysis_text: str
    build_command_json: str


@dataclass
class ConfidenceExtractionInput:
    run_id: str
    analysis_text: str


@dataclass
class ReconcileReasoningInput:
    run_id: str
    requested_deps_json: str
    probe_results_json: str


@dataclass
class ReconcileDepsExtractionInput:
    run_id: str
    reasoning_text: str
    probe_results_json: str


@dataclass
class DiscoveryReasoningInput:
    run_id: str
    repo_url: str
    commit_sha: str | None
    repo_path: str
