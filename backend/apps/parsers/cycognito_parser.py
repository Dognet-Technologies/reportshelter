"""
CyCognito JSON parser.

CyCognito exports a JSON array of issues:
  id               — unique issue ID (e.g. "issue/2.3.45-o-")
  affected_asset   — asset identifier
  potential_threat — threat category
  base_severity_score — float 0-10
  issue_status     — new | reopened | resolved
  mitre_attack_technique_name — MITRE ATT&CK technique
  references[]     — list of reference URLs
  compliance_violations[] — compliance standards violated
  package          — scanner/module that detected it
  last_detected    — ISO-8601 timestamp
  remediation_* fields — remediation guidance
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


def _score_to_risk(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class CyCognitoParser(BaseParser):
    """Parser for CyCognito JSON issue exports."""

    tool_name = "cycognito"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid CyCognito JSON: {exc}") from exc

        if isinstance(data, dict):
            items = data.get("issues") or data.get("results") or [data]
        elif isinstance(data, list):
            items = data
        else:
            raise ParserError("Unexpected CyCognito JSON structure.")

        results: list[NormalizedVulnerability] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            # Skip resolved issues
            status = (item.get("issue_status") or "").lower()
            if status == "resolved":
                continue

            issue_id = item.get("id") or ""
            asset = item.get("affected_asset") or ""
            threat = item.get("potential_threat") or ""
            score = item.get("base_severity_score")
            mitre = item.get("mitre_attack_technique_name") or ""
            refs = item.get("references") or []
            compliance = item.get("compliance_violations") or []
            package = item.get("package") or ""

            title = threat or issue_id or "CyCognito Finding"
            if mitre:
                title += f" ({mitre})"

            description = f"CyCognito detected: {threat}\nAsset: {asset}"
            if mitre:
                description += f"\nMITRE ATT&CK: {mitre}"
            if compliance:
                description += f"\nCompliance: {', '.join(compliance[:5])}"
            if package:
                description += f"\nModule: {package}"

            # Parse host from asset (format: "ip/1.2.3.4" or "domain/example.com")
            host = asset
            if "/" in asset:
                host = asset.split("/", 1)[1]

            ref_urls = [r for r in refs if isinstance(r, str)]
            remediation = "\n".join(ref_urls[:3]) if ref_urls else ""

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=remediation,
                affected_host=host,
                cvss_score=float(score) if score else None,
                risk_level=_score_to_risk(float(score) if score else None),
                evidence_code=description[:4096],
                source="cycognito",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return results
