"""
AWS Security Hub JSON parser.

The exported JSON has a top-level "findings" array. Each finding:
  Title          — finding title
  Description    — finding description
  Severity.Label — CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
  Remediation.Recommendation.Text — remediation text
  Remediation.Recommendation.Url  — remediation URL
  Resources[]    — affected AWS resources
    .Id    — resource ARN
    .Type  — e.g. "AwsEc2Instance"
    .Region
  Types[]        — finding type classification
  Id             — finding ARN (unique)
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
    "none": "info",
}


def _sev(label: str) -> str:
    return _SEV_MAP.get((label or "").lower(), "info")


class AWSSecurityHubParser(BaseParser):
    """Parser for AWS Security Hub JSON exports."""

    tool_name = "awssecurityhub"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid AWS Security Hub JSON: {exc}") from exc

        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            findings = data.get("findings") or data.get("Findings") or []
        else:
            raise ParserError("Unexpected AWS Security Hub JSON structure.")

        results: list[NormalizedVulnerability] = []

        for f in findings:
            if not isinstance(f, dict):
                continue

            title = f.get("Title") or "AWS Security Hub Finding"
            description = f.get("Description") or ""
            severity_label = (f.get("Severity") or {}).get("Label") or "INFORMATIONAL"
            severity = _sev(severity_label)

            remediation = ""
            rem_block = (f.get("Remediation") or {}).get("Recommendation") or {}
            rem_text = rem_block.get("Text") or ""
            rem_url = rem_block.get("Url") or ""
            if rem_text:
                remediation = rem_text
            if rem_url:
                remediation += f"\nSee: {rem_url}"

            # Resources — use first resource as affected host
            resources = f.get("Resources") or []
            affected_host = ""
            if resources:
                r0 = resources[0]
                affected_host = r0.get("Id") or r0.get("Type") or ""
                # truncate long ARNs for readability
                if len(affected_host) > 120:
                    affected_host = affected_host[-120:]

            finding_id = f.get("Id") or ""
            types = f.get("Types") or []
            category = types[0] if types else ""

            evidence = f"Finding ID: {finding_id}\nResources: {len(resources)}"
            if types:
                evidence += f"\nTypes: {'; '.join(types[:3])}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=remediation,
                affected_host=affected_host,
                risk_level=severity,
                category=category,
                evidence_code=evidence[:4096],
                source="awssecurityhub",
                raw_output=json.dumps(f, default=str)[:2048],
            ))

        return results
