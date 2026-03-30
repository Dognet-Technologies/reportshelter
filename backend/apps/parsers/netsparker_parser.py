"""
Netsparker / Invicti JSON parser.

Netsparker Enterprise and Invicti use the same JSON export format as
Acunetix 360:
  Target.Url
  Vulnerabilities[]
    Name
    Severity (0=info, 1=low, 2=medium, 3=high, 4=critical)
    Classification.Cvss.BaseScore.Value
    Classification.Cvss.Vector
    Classification.Cwe
    Classification.Owasp
    Description  (HTML)
    RemedialProcedure (HTML)
    Url / AffectedUrls[]

The acunetix_parser already handles this format. This parser delegates
to the same JSON path with source="netsparker".
"""

from __future__ import annotations

import json
import logging
import re
from typing import IO
from urllib.parse import urlparse

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_INT = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
_HTML_TAG = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    return _HTML_TAG.sub("", text or "").strip()


def _sev(val) -> str:
    try:
        return _SEV_INT.get(int(val), "info")
    except (TypeError, ValueError):
        mapping = {"critical": "critical", "high": "high", "medium": "medium",
                   "low": "low", "info": "info", "information": "info"}
        return mapping.get((str(val) or "").lower(), "info")


class NetsparkerParser(BaseParser):
    """Parser for Netsparker / Invicti JSON reports."""

    tool_name = "netsparker"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Netsparker JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("Netsparker JSON root must be an object.")

        target_url = (data.get("Target") or {}).get("Url") or ""
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port: int | None = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80

        vulns = data.get("Vulnerabilities") or []
        results: list[NormalizedVulnerability] = []

        for v in vulns:
            cls = v.get("Classification") or {}
            cvss_block = cls.get("Cvss") or {}
            base_score_block = cvss_block.get("BaseScore") or {}
            cvss_score_raw = base_score_block.get("Value")
            cvss_score: float | None = None
            try:
                cvss_score = float(cvss_score_raw) if cvss_score_raw is not None else None
            except (TypeError, ValueError):
                pass
            cvss_vector = cvss_block.get("Vector") or ""

            cwe = str(cls.get("Cwe") or "")
            if cwe and cwe.isdigit():
                cwe = f"CWE-{cwe}"

            name = v.get("Name") or v.get("Title") or "Netsparker Finding"
            description = _strip_html(v.get("Description") or "")
            remediation = _strip_html(v.get("RemedialProcedure") or v.get("Recommendation") or "")
            severity = _sev(v.get("Severity"))

            url = v.get("Url") or (
                (v.get("AffectedUrls") or [{}])[0].get("Url", "") if v.get("AffectedUrls") else ""
            ) or target_url

            results.append(NormalizedVulnerability(
                title=name,
                description=description,
                remediation=remediation,
                affected_host=host,
                affected_port=port,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                risk_level=severity,
                category=cwe,
                evidence_code=f"URL: {url}\nCWE: {cwe}",
                source="netsparker",
                raw_output=json.dumps(v, default=str)[:2048],
            ))

        return results
