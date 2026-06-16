from src.analyzer.differ import DiffType, diff_sboms
from src.analyzer.parser import NormalizedPackage


def _pkg(name: str, version: str, *, purl: str | None = None, sha: str | None = None) -> NormalizedPackage:
    return NormalizedPackage(
        purl=purl,
        name=name,
        version=version,
        name_version=f"{name}@{version}",
        sha256=sha,
    )


def test_name_version_mismatch_is_detected_when_only_one_version_per_side() -> None:
    sbomit = [_pkg("foo", "1.0.0")]
    syft = [_pkg("foo", "2.0.0")]

    diff = diff_sboms(sbomit, syft)

    version_mismatches = [e for e in diff.entries if e.diff_type == DiffType.VERSION_MISMATCH]
    assert len(version_mismatches) == 1
    assert version_mismatches[0].package_name == "foo"
    assert version_mismatches[0].sbomit_value == "1.0.0"
    assert version_mismatches[0].syft_value == "2.0.0"
    assert version_mismatches[0].details.get("match_method") == "name"

    only_in = [e for e in diff.entries if e.diff_type in (DiffType.ONLY_IN_SBOMIT, DiffType.ONLY_IN_SYFT)]
    assert only_in == []


def test_no_diff_when_same_name_has_same_version_set_in_both_sboms() -> None:
    sbomit = [_pkg("foo", "1.0.0"), _pkg("foo", "2.0.0")]
    syft = [_pkg("foo", "1.0.0"), _pkg("foo", "2.0.0")]

    diff = diff_sboms(sbomit, syft)

    assert diff.entries == []


def test_unmatched_without_hash_is_still_reported_only_in_side() -> None:
    sbomit = [_pkg("foo", "1.0.0")]
    syft: list[NormalizedPackage] = []

    diff = diff_sboms(sbomit, syft)

    assert len(diff.entries) == 1
    assert diff.entries[0].diff_type == DiffType.ONLY_IN_SBOMIT
    assert diff.entries[0].package_name == "foo"

