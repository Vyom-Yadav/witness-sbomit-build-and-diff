from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from src.analyzer.parser import NormalizedPackage


class DiffType(StrEnum):
    VERSION_MISMATCH = "version_mismatch"
    PURL_MISMATCH = "purl_mismatch"
    HASH_MISMATCH = "hash_mismatch"
    ONLY_IN_SBOMIT = "only_in_sbomit"
    ONLY_IN_SYFT = "only_in_syft"
    LICENSE_MISMATCH = "license_mismatch"


@dataclass
class DiffEntry:
    diff_type: DiffType
    package_name: str
    purl: str | None
    sha256: str | None
    sbomit_value: str
    syft_value: str
    details: dict = field(default_factory=dict)


@dataclass
class SBOMDiff:
    entries: list[DiffEntry]
    total_sbomit: int
    total_syft: int
    hash_matched: int
    purl_matched: int
    similarity_score: float


def diff_sboms(
    sbomit_packages: list[NormalizedPackage],
    syft_packages: list[NormalizedPackage],
) -> SBOMDiff:
    """Compare two sets of normalized SBOM packages using hash-first matching."""
    from src.analyzer.parser import index_by_hash

    a_by_hash = index_by_hash(sbomit_packages)
    b_by_hash = index_by_hash(syft_packages)

    def _pkg_key(pkg: NormalizedPackage) -> tuple[str, str, str | None, str | None]:
        return (pkg.name, pkg.version, pkg.purl, pkg.sha256)

    entries: list[DiffEntry] = []

    # 1. Hash-first matching (primary identity)
    common_hash = set(a_by_hash) & set(b_by_hash)

    # Flag: same hash, different version (discrepancy)
    for h in common_hash:
        a_pkg = a_by_hash[h]
        b_pkg = b_by_hash[h]
        if a_pkg.version != b_pkg.version:
            entries.append(DiffEntry(
                diff_type=DiffType.VERSION_MISMATCH,
                package_name=a_pkg.name,
                purl=a_pkg.purl or b_pkg.purl,
                sha256=h,
                sbomit_value=a_pkg.version,
                syft_value=b_pkg.version,
                details={
                    "match_method": "hash",
                    "note": "Same content hash but different versions — tools disagree",
                },
            ))

    # Flag: same hash, different PURL
    for h in common_hash:
        a_pkg = a_by_hash[h]
        b_pkg = b_by_hash[h]
        if a_pkg.purl != b_pkg.purl:
            entries.append(DiffEntry(
                diff_type=DiffType.PURL_MISMATCH,
                package_name=a_pkg.name,
                purl=a_pkg.purl or b_pkg.purl,
                sha256=h,
                sbomit_value=a_pkg.purl or "none",
                syft_value=b_pkg.purl or "none",
                details={"match_method": "hash"},
            ))

    # Track matched packages to avoid double-reporting across matching stages.
    matched_a_keys = {_pkg_key(a_by_hash[h]) for h in common_hash}
    matched_b_keys = {_pkg_key(b_by_hash[h]) for h in common_hash}

    # 2. For packages not matched by hash, try PURL
    a_no_hash = [pkg for pkg in sbomit_packages if pkg.sha256 not in common_hash]
    b_no_hash = [pkg for pkg in syft_packages if pkg.sha256 not in common_hash]

    a_remaining_by_purl = {pkg.purl: pkg for pkg in a_no_hash if pkg.purl}
    b_remaining_by_purl = {pkg.purl: pkg for pkg in b_no_hash if pkg.purl}

    common_purl = set(a_remaining_by_purl) & set(b_remaining_by_purl)

    for purl in common_purl:
        a_pkg = a_remaining_by_purl[purl]
        b_pkg = b_remaining_by_purl[purl]
        matched_a_keys.add(_pkg_key(a_pkg))
        matched_b_keys.add(_pkg_key(b_pkg))
        if a_pkg.version != b_pkg.version:
            entries.append(DiffEntry(
                diff_type=DiffType.VERSION_MISMATCH,
                package_name=a_pkg.name,
                purl=purl,
                sha256=None,
                sbomit_value=a_pkg.version,
                syft_value=b_pkg.version,
                details={"match_method": "purl"},
            ))
        if a_pkg.sha256 and b_pkg.sha256 and a_pkg.sha256 != b_pkg.sha256:
            entries.append(DiffEntry(
                diff_type=DiffType.HASH_MISMATCH,
                package_name=a_pkg.name,
                purl=purl,
                sha256=None,
                sbomit_value=a_pkg.sha256,
                syft_value=b_pkg.sha256,
                details={"match_method": "purl"},
            ))

    # 3. Name-based version-set mismatch for remaining packages.
    # This catches cases like: A has foo@1.0, B has foo@2.0 (same name, different version sets).
    a_unmatched = [pkg for pkg in sbomit_packages if _pkg_key(pkg) not in matched_a_keys]
    b_unmatched = [pkg for pkg in syft_packages if _pkg_key(pkg) not in matched_b_keys]

    a_by_name: dict[str, list[NormalizedPackage]] = {}
    b_by_name: dict[str, list[NormalizedPackage]] = {}
    for pkg in a_unmatched:
        a_by_name.setdefault(pkg.name, []).append(pkg)
    for pkg in b_unmatched:
        b_by_name.setdefault(pkg.name, []).append(pkg)

    names_in_both = set(a_by_name) & set(b_by_name)
    for name in names_in_both:
        a_versions = sorted({pkg.version for pkg in a_by_name[name]})
        b_versions = sorted({pkg.version for pkg in b_by_name[name]})

        if a_versions == b_versions:
            for pkg in a_by_name[name]:
                matched_a_keys.add(_pkg_key(pkg))
            for pkg in b_by_name[name]:
                matched_b_keys.add(_pkg_key(pkg))
            continue

        if a_versions != b_versions:
            entries.append(DiffEntry(
                diff_type=DiffType.VERSION_MISMATCH,
                package_name=name,
                purl=None,
                sha256=None,
                sbomit_value=", ".join(a_versions),
                syft_value=", ".join(b_versions),
                details={
                    "match_method": "name",
                    "note": "Same package name appears with different version sets",
                },
            ))
            for pkg in a_by_name[name]:
                matched_a_keys.add(_pkg_key(pkg))
            for pkg in b_by_name[name]:
                matched_b_keys.add(_pkg_key(pkg))

    # 4. Packages only in one SBOM (not matched by hash, PURL, or name-based version set).
    a_unmatched = [pkg for pkg in sbomit_packages if _pkg_key(pkg) not in matched_a_keys]
    b_unmatched = [pkg for pkg in syft_packages if _pkg_key(pkg) not in matched_b_keys]

    for pkg in a_unmatched:
        entries.append(DiffEntry(
            diff_type=DiffType.ONLY_IN_SBOMIT,
            package_name=pkg.name,
            purl=pkg.purl,
            sha256=pkg.sha256,
            sbomit_value=pkg.version,
            syft_value="",
        ))

    for pkg in b_unmatched:
        entries.append(DiffEntry(
            diff_type=DiffType.ONLY_IN_SYFT,
            package_name=pkg.name,
            purl=pkg.purl,
            sha256=pkg.sha256,
            sbomit_value="",
            syft_value=pkg.version,
        ))

    # 5. License mismatches for hash-matched packages
    for h in common_hash:
        a_pkg = a_by_hash[h]
        b_pkg = b_by_hash[h]
        if a_pkg.license and b_pkg.license and a_pkg.license != b_pkg.license:
            entries.append(DiffEntry(
                diff_type=DiffType.LICENSE_MISMATCH,
                package_name=a_pkg.name,
                purl=a_pkg.purl,
                sha256=h,
                sbomit_value=a_pkg.license,
                syft_value=b_pkg.license,
                details={"match_method": "hash"},
            ))

    # Calculate similarity
    total_unique = len(set(a_by_hash) | set(b_by_hash))
    similarity = len(common_hash) / total_unique if total_unique > 0 else 1.0

    return SBOMDiff(
        entries=entries,
        total_sbomit=len(sbomit_packages),
        total_syft=len(syft_packages),
        hash_matched=len(common_hash),
        purl_matched=len(common_purl),
        similarity_score=similarity,
    )


def diff_to_dicts(diff: SBOMDiff) -> list[dict]:
    """Convert SBOMDiff entries to list of dicts for storage."""
    return [
        {
            "diff_type": entry.diff_type.value,
            "package_name": entry.package_name,
            "purl": entry.purl,
            "sha256": entry.sha256,
            "sbomit_value": entry.sbomit_value,
            "syft_value": entry.syft_value,
            "details": entry.details,
        }
        for entry in diff.entries
    ]
