from __future__ import annotations

from dataclasses import dataclass

from src.analyzer.differ import DiffEntry, SBOMDiff


@dataclass
class DiffReport:
    summary: str
    details: str
    json_output: dict


def generate_report(diff: SBOMDiff) -> DiffReport:
    """Generate human-readable and JSON reports from SBOMDiff."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("SBOM ACCURACY DIFF REPORT")
    lines.append("=" * 60)
    lines.append(f"sbomit packages: {diff.total_sbomit}")
    lines.append(f"syft packages:   {diff.total_syft}")
    lines.append(f"Hash matched:    {diff.hash_matched}")
    lines.append(f"PURL matched:    {diff.purl_matched}")
    lines.append(f"Similarity:      {diff.similarity_score:.1%}")
    lines.append(f"Total diffs:     {len(diff.entries)}")
    lines.append("=" * 60)

    by_type: dict[str, list[DiffEntry]] = {}
    for entry in diff.entries:
        by_type.setdefault(entry.diff_type.value, []).append(entry)

    for diff_type, entries in by_type.items():
        lines.append(f"\n--- {diff_type.upper()} ({len(entries)} entries) ---")
        for entry in entries:
            purl_str = f" [{entry.purl}]" if entry.purl else ""
            hash_str = f" (sha256: {entry.sha256[:16]}...)" if entry.sha256 else ""
            lines.append(f"  {entry.package_name}{purl_str}{hash_str}")
            if entry.diff_type.value in ("version_mismatch", "license_mismatch"):
                lines.append(f"    sbomit: {entry.sbomit_value}")
                lines.append(f"    syft:   {entry.syft_value}")
            elif entry.diff_type.value == "only_in_sbomit":
                lines.append(f"    sbomit: {entry.sbomit_value} (not in syft)")
            elif entry.diff_type.value == "only_in_syft":
                lines.append(f"    syft: {entry.syft_value} (not in sbomit)")
            elif entry.diff_type.value == "hash_mismatch":
                lines.append(f"    sbomit hash: {entry.sbomit_value[:32]}...")
                lines.append(f"    syft hash:   {entry.syft_value[:32]}...")

    lines.append("\n" + "=" * 60)
    lines.append("END OF REPORT")
    lines.append("=" * 60)

    json_output = {
        "total_sbomit": diff.total_sbomit,
        "total_syft": diff.total_syft,
        "hash_matched": diff.hash_matched,
        "purl_matched": diff.purl_matched,
        "similarity_score": diff.similarity_score,
        "diffs": [
            {
                "diff_type": e.diff_type.value,
                "package_name": e.package_name,
                "purl": e.purl,
                "sha256": e.sha256,
                "sbomit_value": e.sbomit_value,
                "syft_value": e.syft_value,
                "details": e.details,
            }
            for e in diff.entries
        ],
    }

    return DiffReport(
        summary=f"{len(diff.entries)} diffs found ({diff.similarity_score:.1%} similarity)",
        details="\n".join(lines),
        json_output=json_output,
    )
