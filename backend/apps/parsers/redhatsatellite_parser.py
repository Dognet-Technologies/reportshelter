"""
Red Hat Satellite JSON parser.

Satellite exports errata (advisories) as:
  {
    "results": [
      {
        "errata_id": "RHSA-2021:1234",
        "title": "...",
        "type": "security|bugfix|enhancement",
        "severity": "Critical|Important|Moderate|Low|None",
        "description": "...",
        "solution": "...",
        "cves": [{"cve": "CVE-2021-XXXX"}],
        "packages": ["package-version.rpm"],
        "hosts_applicable_count": 5
      }
    ]
  }

Only security errata are reported.
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
    "important": "high",
    "moderate": "medium",
    "low": "low",
    "none": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower(), "info")


class RedHatSatelliteParser(BaseParser):
    """Parser for Red Hat Satellite errata JSON exports."""

    tool_name = "redhatsatellite"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Red Hat Satellite JSON: {exc}") from exc

        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("results") or data.get("errata") or []
        else:
            raise ParserError("Unexpected Red Hat Satellite JSON structure.")

        results: list[NormalizedVulnerability] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            errata_type = (item.get("type") or "").lower()
            # Only report security errata by default; bugfix/enhancement are low value
            severity = _sev(item.get("severity") or "none")

            errata_id = item.get("errata_id") or item.get("uuid") or ""
            title = item.get("title") or item.get("name") or errata_id or "Red Hat Errata"
            description = item.get("description") or item.get("summary") or ""
            solution = item.get("solution") or ""
            packages = item.get("packages") or []
            cves = item.get("cves") or []
            hosts_count = item.get("hosts_applicable_count") or 0

            cve_list = []
            for cve in cves:
                if isinstance(cve, dict):
                    cve_id = cve.get("cve") or cve.get("name") or ""
                elif isinstance(cve, str):
                    cve_id = cve
                else:
                    continue
                if cve_id:
                    cve_list.append(cve_id)

            description_full = description
            if packages:
                description_full += f"\n\nAffected packages: {', '.join(packages[:10])}"
            if hosts_count:
                description_full += f"\nHosts affected: {hosts_count}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description_full,
                remediation=solution,
                cve_id=cve_list,
                risk_level=severity,
                evidence_code=f"Errata: {errata_id}\nType: {errata_type}\nHosts: {hosts_count}",
                source="redhatsatellite",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return results
