"""
GitLab Container Scan JSON parser (v14 / v15 schema).

Format: {"version": "3.0.0", "vulnerabilities": [...]}
Each vulnerability:
  id           — SHA hash ID
  description  — description
  severity     — Critical | High | Medium | Low | Unknown | Info
  solution     — remediation
  location
    dependency.package.name   — package name
    dependency.version        — installed version
    operating_system          — e.g. "debian:9.4"
    image                     — container image reference
  identifiers[]
    type   — "cve" | "cwe" | "gemnasium" etc.
    name   — e.g. "CVE-2019-3462"
    value
    url
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower(), "info")


class GitLabContainerScanParser(BaseParser):
    """Parser for GitLab Container Scanning JSON reports."""

    tool_name = "gitlab_container_scan"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid GitLab Container Scan JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("GitLab Container Scan JSON root must be an object.")

        vulns = data.get("vulnerabilities") or []
        results: list[NormalizedVulnerability] = []

        for v in vulns:
            if not isinstance(v, dict):
                continue

            description = v.get("description") or ""
            severity = _sev(v.get("severity") or "")
            solution = v.get("solution") or ""

            location = v.get("location") or {}
            dep = location.get("dependency") or {}
            pkg_name = (dep.get("package") or {}).get("name") or ""
            pkg_version = dep.get("version") or ""
            os_info = location.get("operating_system") or ""
            image = location.get("image") or ""

            identifiers = v.get("identifiers") or []
            cve_list = [
                i["value"] for i in identifiers
                if isinstance(i, dict) and (i.get("type") or "").lower() == "cve"
            ]
            cwe_list = [
                i["value"] for i in identifiers
                if isinstance(i, dict) and (i.get("type") or "").lower() == "cwe"
            ]

            title = cve_list[0] if cve_list else (
                f"Vulnerability in {pkg_name}" if pkg_name else "Container Vulnerability"
            )
            if pkg_name:
                title += f" ({pkg_name} {pkg_version})"

            affected_host = image or os_info

            evidence = f"Image: {image}\nOS: {os_info}\nPackage: {pkg_name} {pkg_version}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=solution,
                affected_host=affected_host,
                cve_id=cve_list,
                risk_level=severity,
                category=cwe_list[0] if cwe_list else "",
                evidence_code=evidence[:4096],
                source="gitlab_container_scan",
                raw_output=json.dumps(v, default=str)[:2048],
            ))

        return results
