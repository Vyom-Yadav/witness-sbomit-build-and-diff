from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NormalizedPackage:
    purl: str | None
    name: str
    version: str
    name_version: str
    sha256: str | None
    all_checksums: dict[str, str] = field(default_factory=dict)
    supplier: str | None = None
    license: str | None = None
    download_location: str | None = None


def parse_spdx_json(filepath: str) -> list[NormalizedPackage]:
    """Parse an SPDX v2.3 JSON file and return normalized packages."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"SBOM file not found: {filepath}")

    with open(path) as f:
        doc = json.load(f)

    packages = doc.get("packages", [])
    results: list[NormalizedPackage] = []

    for pkg in packages:
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        name_version = f"{name}@{version}" if version else name

        # Extract PURL from externalRefs
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break

        # Extract checksums
        checksums: dict[str, str] = {}
        sha256 = None
        for cs in pkg.get("checksums", []):
            algo = cs.get("algorithm", "").upper()
            value = cs.get("checksumValue", "")
            checksums[algo] = value
            if algo == "SHA256":
                sha256 = value

        # Extract license
        license_info = pkg.get("licenseConcluded", None)
        if not license_info or license_info == "NOASSERTION":
            license_info = pkg.get("licenseDeclared", None)

        results.append(NormalizedPackage(
            purl=purl,
            name=name,
            version=version,
            name_version=name_version,
            sha256=sha256,
            all_checksums=checksums,
            supplier=purl.split("/")[1] if purl and "/" in purl else None,
            license=license_info if license_info and license_info != "NOASSERTION" else None,
            download_location=pkg.get("downloadLocation"),
        ))

    return results


def index_by_hash(packages: list[NormalizedPackage]) -> dict[str, NormalizedPackage]:
    """Index packages by SHA-256 hash. Packages without hash are excluded."""
    return {pkg.sha256: pkg for pkg in packages if pkg.sha256}


def index_by_purl(packages: list[NormalizedPackage]) -> dict[str, NormalizedPackage]:
    """Index packages by PURL. Packages without PURL are excluded."""
    return {pkg.purl: pkg for pkg in packages if pkg.purl}


def index_by_name_version(packages: list[NormalizedPackage]) -> dict[str, NormalizedPackage]:
    """Index packages by name@version."""
    return {pkg.name_version: pkg for pkg in packages if pkg.name_version}
