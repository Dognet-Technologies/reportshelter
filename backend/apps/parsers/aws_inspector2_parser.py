"""
AWS Inspector2 JSON parser.

Format: {"findings": [...]}
Each finding:
  description          — finding description
  severity             — CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
  findingArn           — unique ARN
  inspectorScore       — numeric score (0-10)
  inspectorScoreDetails.adjustedCvss.scoringVector — CVSS vector
  epss.score           — EPSS score (0-1)
  packageVulnerabilityDetails
    .vulnerabilityId   — CVE ID
    .cvss[].baseScore / .scoringVector
    .vulnerablePackages[].name / .version / .remediation
  resources[].type / .id — affected resource
  title                — optional title (not always present)
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
    "informational": "info",
    "untriaged": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower(), "info")


class AWSInspector2Parser(BaseParser):
    """Parser for AWS Inspector2 JSON exports."""

    tool_name = "aws_inspector2"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid AWS Inspector2 JSON: {exc}") from exc

        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = data.get("findings") or data.get("Findings") or []
        else:
            raise ParserError("Unexpected AWS Inspector2 JSON structure.")

        results: list[NormalizedVulnerability] = []

        for f in findings:
            if not isinstance(f, dict):
                continue

            description = f.get("description") or ""
            severity = _sev(f.get("severity") or "")
            inspector_score = f.get("inspectorScore")

            # CVSS
            cvss_score: float | None = None
            cvss_vector = ""
            score_details = (f.get("inspectorScoreDetails") or {}).get("adjustedCvss") or {}
            if score_details:
                cvss_score = score_details.get("score") or inspector_score
                cvss_vector = score_details.get("scoringVector") or ""

            # EPSS
            epss: float | None = None
            epss_block = f.get("epss") or {}
            if epss_block:
                epss = epss_block.get("score")

            # CVE details
            pkg_details = f.get("packageVulnerabilityDetails") or {}
            cve_id = pkg_details.get("vulnerabilityId") or ""
            cve_list = [cve_id] if cve_id else []

            # CVSS from package details if not in score_details
            if not cvss_score:
                for cvss_entry in (pkg_details.get("cvss") or []):
                    if cvss_entry.get("baseScore"):
                        cvss_score = float(cvss_entry["baseScore"])
                        cvss_vector = cvss_entry.get("scoringVector") or ""
                        break

            # Affected packages
            vuln_pkgs = pkg_details.get("vulnerablePackages") or []
            pkg_info = ""
            remediation = ""
            for pkg in vuln_pkgs:
                name = pkg.get("name") or ""
                version = pkg.get("version") or ""
                fix = pkg.get("fixedInVersion") or ""
                rem = pkg.get("remediation") or ""
                pkg_info += f"\n  {name} {version}"
                if fix:
                    pkg_info += f" → fix: {fix}"
                if rem and not remediation:
                    remediation = rem

            # Resources
            resources = f.get("resources") or []
            affected_host = ""
            if resources:
                r0 = resources[0]
                affected_host = r0.get("id") or r0.get("type") or ""
                if len(affected_host) > 120:
                    affected_host = affected_host[-120:]

            title = f.get("title") or (f"Inspector2: {cve_id}" if cve_id else "AWS Inspector2 Finding")
            if not title:
                title = description[:80] or "AWS Inspector2 Finding"

            evidence = f"CVE: {cve_id}\nInspector Score: {inspector_score}"
            if pkg_info:
                evidence += f"\nPackages:{pkg_info}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=remediation,
                affected_host=affected_host,
                cve_id=cve_list,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                epss_score=epss,
                risk_level=severity,
                evidence_code=evidence[:4096],
                source="aws_inspector2",
                raw_output=json.dumps(f, default=str)[:2048],
            ))

        return results
