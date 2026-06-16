from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class DiffClassification(BaseModel):
    """Classification of a single diff entry."""
    package_name: str
    purl: str | None = None
    diff_type: str
    sbomit_value: str | None = None
    syft_value: str | None = None
    classification: Literal[
        "sbomit_correct",
        "syft_correct",
        "inconclusive",
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    evidence_files: list[str] = Field(default_factory=list)


class ClassificationResult(BaseModel):
    """Result of classifying all diffs in a build."""
    classifications: list[DiffClassification]
    metrics: AgentMetrics


class AgentMetrics(BaseModel):
    """Aggregate metrics for the entire build."""
    total_diffs: int
    classified: dict[str, int]
    avg_confidence: float
    sbomit_accuracy: float
    syft_accuracy: float
    inconclusive_count: int
    human_overridden: int = 0
    token_usage: int = 0
