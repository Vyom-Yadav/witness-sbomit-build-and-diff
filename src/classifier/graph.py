from __future__ import annotations

from typing import Any, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage

from src.classifier.models import DiffClassification
from src.classifier.prompts import CLASSIFICATION_SYSTEM, build_classification_prompt
from src.config import settings


class ClassifierState(TypedDict):
    diff_entries: list[dict]
    current_index: int
    classifications: list[dict]
    loop_count: int


async def classify_diffs(diff_entries: list[dict], context_output_path: str = "") -> dict:
    """Classify all diff entries using the LLM agent.

    Args:
        diff_entries: List of diff dicts from analyzer.differ.diff_to_dicts()
        context_output_path: If provided, save full prompt/response pairs to this file

    Returns:
        dict with 'classifications', 'metrics', and 'classifier_context_path' keys
    """
    import json
    from pathlib import Path

    if not diff_entries:
        return {
            "classifications": [],
            "metrics": _empty_metrics(),
            "classifier_context_path": "",
        }

    classifications: list[dict] = []

    for entry in diff_entries:
        cls = await _classify_single_entry(entry)
        classifications.append(cls)

    if context_output_path:
        Path(context_output_path).write_text(json.dumps(classifications, indent=2))

    metrics = _compute_metrics(classifications)

    return {
        "classifications": classifications,
        "metrics": metrics,
        "classifier_context_path": context_output_path,
    }


async def _classify_single_entry(entry: dict) -> dict:
    """Classify a single diff entry."""
    from langchain_openrouter import ChatOpenRouter

    llm = ChatOpenRouter(
        model=settings.classifier_model,
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        temperature=0,
    )
    llm_structured = llm.with_structured_output(DiffClassification)

    prompt = build_classification_prompt(entry, context_files=[])

    messages = [
        SystemMessage(content=CLASSIFICATION_SYSTEM),
        HumanMessage(content=prompt),
    ]

    try:
        result: Any = llm_structured.invoke(messages)
        cls_dict = result.model_dump() if hasattr(result, "model_dump") else dict(result)
        cls_dict["system_prompt"] = CLASSIFICATION_SYSTEM
        cls_dict["user_prompt"] = prompt
        return cls_dict
    except Exception:
        return {
            "package_name": entry["package_name"],
            "purl": entry.get("purl"),
            "diff_type": entry["diff_type"],
            "sbomit_value": entry.get("sbomit_value"),
            "syft_value": entry.get("syft_value"),
            "classification": "inconclusive",
            "confidence": 0.0,
            "reasoning": "Classification failed due to LLM error",
            "evidence_files": [],
            "system_prompt": CLASSIFICATION_SYSTEM,
            "user_prompt": prompt,
        }


def _compute_metrics(classifications: list[dict]) -> dict:
    """Compute aggregate metrics from classification results."""
    if not classifications:
        return _empty_metrics()

    classified_counts: dict[str, int] = {}
    total_confidence = 0.0
    sbomit_correct = 0
    syft_correct = 0
    inconclusive = 0

    for cls in classifications:
        c = cls["classification"]
        classified_counts[c] = classified_counts.get(c, 0) + 1
        total_confidence += cls.get("confidence", 0)

        if c == "sbomit_correct":
            sbomit_correct += 1
        elif c == "syft_correct":
            syft_correct += 1
        elif c == "inconclusive":
            inconclusive += 1

    total = len(classifications)
    decisions = total - inconclusive

    return {
        "total_diffs": total,
        "classified": classified_counts,
        "avg_confidence": total_confidence / total if total > 0 else 0.0,
        "sbomit_accuracy": sbomit_correct / decisions if decisions > 0 else 0.0,
        "syft_accuracy": syft_correct / decisions if decisions > 0 else 0.0,
        "inconclusive_count": inconclusive,
        "human_overridden": 0,
        "token_usage": 0,
    }


def _empty_metrics() -> dict:
    return {
        "total_diffs": 0,
        "classified": {},
        "avg_confidence": 0.0,
        "sbomit_accuracy": 0.0,
        "syft_accuracy": 0.0,
        "inconclusive_count": 0,
        "human_overridden": 0,
        "token_usage": 0,
    }
