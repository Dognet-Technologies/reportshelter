"""
Cargo Audit JSON parser.

cargo audit --json produces a JSON report:
  vulnerabilities.list[].advisory  — advisory details
    .id       — RUSTSEC ID
    .title    — advisory title
    .description
    .aliases  — list of CVE IDs
    .cvss     — optional CVSS vector string (CVSS:3.x/...)
    .url      — advisory URL
    .categories
  vulnerabilities.list[].versions.patched  — patched version ranges
  vulnerabilities.list[].package.name / .version — affected package
"""

from __future__ import annotations

import json
import logging
import re
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_CVSS_SCORE_RE = re.compile(r"CVSS:3\.\d/[A-Z:/]+")


def _cvss_score(vector: str | None) -> float | None:
    """Return None — cargo audit does not embed the numeric score, only the vector."""
    return None


class CargoAuditParser(BaseParser):
    """Parser for cargo audit --json output."""

    tool_name = "cargo_audit"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid cargo audit JSON: {exc}") from exc

        vuln_block = data.get("vulnerabilities") or {}
        vuln_list = vuln_block.get("list") or []

        # Also include warnings (unmaintained crates, etc.)
        warnings = data.get("warnings") or {}

        results: list[NormalizedVulnerability] = []

        for entry in vuln_list:
            if not isinstance(entry, dict):
                continue

            advisory = entry.get("advisory") or {}
            pkg = entry.get("package") or {}

            rustsec_id = advisory.get("id") or ""
            title = advisory.get("title") or rustsec_id or "Rust Advisory"
            description = advisory.get("description") or ""
            cve_list: list[str] = [a for a in (advisory.get("aliases") or []) if a.startswith("CVE-")]
            cvss_vector = advisory.get("cvss") or ""
            url = advisory.get("url") or ""
            categories = advisory.get("categories") or []

            pkg_name = pkg.get("name") or ""
            pkg_version = pkg.get("version") or ""
            patched = entry.get("versions", {}).get("patched") or []

            remediation = ""
            if patched:
                remediation = f"Upgrade {pkg_name} to a patched version: {', '.join(patched)}"

            description_full = description
            if pkg_name:
                description_full += f"\n\nAffected package: {pkg_name} {pkg_version}"
            if url:
                description_full += f"\nAdvisory: {url}"

            category = "CWE-1035"  # default: vulnerable dependency
            if categories:
                category = categories[0]

            results.append(NormalizedVulnerability(
                title=title,
                description=description_full,
                remediation=remediation,
                affected_host=pkg_name,
                cve_id=cve_list,
                cvss_vector=cvss_vector,
                risk_level="high",  # cargo audit doesn't always provide severity
                category=category,
                evidence_code=f"RUSTSEC ID: {rustsec_id}\nPackage: {pkg_name} {pkg_version}",
                source="cargo_audit",
                raw_output=json.dumps(entry, default=str)[:2048],
            ))

        # warnings: unmaintained, yanked, etc.
        for warn_type, warn_list in warnings.items():
            if not isinstance(warn_list, list):
                continue
            for w in warn_list:
                advisory = w.get("advisory") or {}
                pkg = w.get("package") or {}
                title = advisory.get("title") or f"Warning: {warn_type}"
                description = advisory.get("description") or f"Package {warn_type}"
                pkg_name = pkg.get("name") or ""
                pkg_version = pkg.get("version") or ""

                results.append(NormalizedVulnerability(
                    title=title,
                    description=description + (f"\n\nPackage: {pkg_name} {pkg_version}" if pkg_name else ""),
                    affected_host=pkg_name,
                    risk_level="low",
                    category="CWE-1035",
                    source="cargo_audit",
                    raw_output=json.dumps(w, default=str)[:2048],
                ))

        return results
