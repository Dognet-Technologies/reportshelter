"""
Cobalt.io CSV parser.

Cobalt pentest platform exports findings as CSV:
  Token, Tag, Title, Type, CreatedAt, BrowserUrl, HttpRequest,
  CriticalityJustification, Description, StepsToReproduce,
  ToolsUsed, SuggestedFix, RequestParams, Prerequisites,
  AssignedTo, EvaluatedResult, ReportUrl, ReportedBy,
  ResearcherUrl, RefKey

Severity is derived from the Tag column (e.g. "#TBD_1") or
CriticalityJustification text. EvaluatedResult values:
  need_fix, carry_risk, accepted_risk, check_mitigation, invalid, null
"""

from __future__ import annotations

import csv
import io
import logging
import re
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_TAG_SEV_RE = re.compile(r"#?TBD_(\d)", re.IGNORECASE)
_SEV_INT = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}

_SKIP_RESULTS = {"invalid", "accepted_risk"}


def _sev_from_tag(tag: str) -> str | None:
    m = _TAG_SEV_RE.search(tag or "")
    if m:
        return _SEV_INT.get(int(m.group(1)), "medium")
    return None


def _sev_from_justification(text: str) -> str:
    text_lower = (text or "").lower()
    if "critical" in text_lower:
        return "critical"
    if "high" in text_lower:
        return "high"
    if "medium" in text_lower:
        return "medium"
    if "low" in text_lower:
        return "low"
    return "medium"


class CobaltParser(BaseParser):
    """Parser for Cobalt.io pentest platform CSV exports."""

    tool_name = "cobalt"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            text = file_obj.read().decode("utf-8", errors="replace")
        except Exception as exc:
            raise ParserError(f"Cannot decode Cobalt CSV: {exc}") from exc

        try:
            reader = csv.DictReader(io.StringIO(text), quotechar="'")
        except Exception as exc:
            raise ParserError(f"Cannot parse Cobalt CSV: {exc}") from exc

        results: list[NormalizedVulnerability] = []

        for row in reader:
            row = {k.strip().lstrip("\ufeff").strip("'"): v.strip().strip("'") if v else "" for k, v in row.items()}

            evaluated_result = (row.get("EvaluatedResult") or "").lower().strip()
            if evaluated_result in _SKIP_RESULTS:
                continue

            title = row.get("Title") or "Cobalt Finding"
            vuln_type = row.get("Type") or ""
            tag = row.get("Tag") or ""
            description = row.get("Description") or ""
            steps = row.get("StepsToReproduce") or ""
            fix = row.get("SuggestedFix") or ""
            criticality = row.get("CriticalityJustification") or ""
            url = row.get("BrowserUrl") or ""
            http_request = (row.get("HttpRequest") or "")[:500]

            # Derive severity from tag or criticality justification
            severity = _sev_from_tag(tag) or _sev_from_justification(criticality)

            # Host from URL
            host = ""
            port: int | None = None
            if url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    host = parsed.hostname or url
                    port = parsed.port
                    if port is None and parsed.scheme:
                        port = 443 if parsed.scheme == "https" else 80
                except Exception:
                    host = url

            full_description = description
            if steps:
                full_description += f"\n\nSteps to Reproduce:\n{steps}"
            if criticality:
                full_description += f"\n\nCriticality: {criticality}"

            evidence = f"Type: {vuln_type}\nURL: {url}"
            if http_request:
                evidence += f"\n\nRequest:\n{http_request}"

            results.append(NormalizedVulnerability(
                title=title,
                description=full_description,
                remediation=fix,
                affected_host=host,
                affected_port=port,
                risk_level=severity,
                category=vuln_type,
                evidence_code=evidence[:4096],
                source="cobalt",
                raw_output=str(dict(list(row.items())[:15]))[:2048],
            ))

        return results
