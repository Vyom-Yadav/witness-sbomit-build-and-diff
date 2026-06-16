from __future__ import annotations

from src.discovery.prompts import CLASSIFIER_SYSTEM_PROMPT


def build_classification_prompt(diff_entry: dict, context_files: list[str]) -> str:
    """Build a prompt for classifying a single diff entry."""
    prompt = f"""\
Analyze the following SBOM diff entry and classify which tool is correct.

## Diff Entry
- Package: {diff_entry['package_name']}
- PURL: {diff_entry.get('purl', 'N/A')}
- Diff Type: {diff_entry['diff_type']}
- sbomit value: {diff_entry.get('sbomit_value', 'N/A')}
- syft value: {diff_entry.get('syft_value', 'N/A')}
"""
    if diff_entry.get("details"):
        prompt += f"- Match method: {diff_entry['details'].get('match_method', 'unknown')}\n"
        if diff_entry["details"].get("note"):
            prompt += f"- Note: {diff_entry['details']['note']}\n"

    if context_files:
        prompt += "\n## Relevant Source Files\n"
        for f in context_files[:3]:
            prompt += f"### {f}\n<file contents here — use tools to read>\n"

    prompt += """
## Instructions
1. Check dependency lock files (go.sum, package-lock.json, Cargo.lock,
   requirements.txt) for the actual pinned version
2. For version mismatches: the lock file is ground truth
   - If match method is `name`, compare version sets per package name
     (e.g., foo@1.0 vs foo@2.0 should be treated as a true mismatch)
3. For hash mismatches: the hash is ground truth for content identity
4. For missing packages: check if it's a test/build-only dependency
5. For license changes: check the package's LICENSE file

## Output
Classify this diff entry. Provide:
- classification (one of: sbomit_correct, syft_correct, inconclusive)
- confidence (0.0 to 1.0)
- reasoning (specific evidence from files)
- evidence_files (list of files that support your conclusion)
"""
    return prompt


CLASSIFICATION_SYSTEM = CLASSIFIER_SYSTEM_PROMPT
