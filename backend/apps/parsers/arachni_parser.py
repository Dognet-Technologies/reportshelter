"""
Arachni JSON/AFR parser.

Arachni --report-save-path=report.afr.json produces:
  {
    "issues": [
      {
        "name":        — vuln name (e.g. "Cross-Site Scripting (XSS)")
        "description": — full description
        "remedy_guidance": — remediation advice
        "severity":    — "high"|"medium"|"low"|"informational"
        "cwe":         — CWE integer
        "references":  — {name: url} dict
        "variations":  — list of instances (url, vector, method)
      }
    ],
    "options": {"url": "..."}
  }
"""

from __future__ import annotations

import json
import logging
from typing import IO
from urllib.parse import urlparse

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower(), "info")


class ArachniParser(BaseParser):
    """Parser for Arachni AFR/JSON reports."""

    tool_name = "arachni"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Arachni JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("Arachni JSON root must be an object.")

        target_url = (data.get("options") or {}).get("url") or ""
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port: int | None = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80

        issues = data.get("issues") or []
        results: list[NormalizedVulnerability] = []

        for issue in issues:
            if not isinstance(issue, dict):
                continue

            name = issue.get("name") or "Arachni Finding"
            description = issue.get("description") or ""
            remediation = issue.get("remedy_guidance") or ""
            severity = _sev(issue.get("severity") or "")
            cwe_int = issue.get("cwe")
            cwe = f"CWE-{cwe_int}" if cwe_int else ""

            # Collect URLs from variations
            variations = issue.get("variations") or []
            affected_urls: list[str] = []
            for var in variations[:5]:
                if isinstance(var, dict):
                    var_url = var.get("url") or ""
                    if var_url:
                        affected_urls.append(var_url)

            # First variation URL as affected host if no target
            if not host and affected_urls:
                p = urlparse(affected_urls[0])
                host = p.hostname or affected_urls[0]
                port = p.port

            refs = issue.get("references") or {}
            ref_text = "\n".join(f"{k}: {v}" for k, v in list(refs.items())[:5])

            evidence = f"Target: {target_url or affected_urls[0] if affected_urls else ''}"
            if affected_urls:
                evidence += f"\nURLs: {chr(10).join(affected_urls)}"
            if ref_text:
                evidence += f"\nRefs:\n{ref_text}"

            results.append(NormalizedVulnerability(
                title=name,
                description=description,
                remediation=remediation,
                affected_host=host,
                affected_port=port,
                risk_level=severity,
                category=cwe,
                evidence_code=evidence[:4096],
                source="arachni",
                raw_output=json.dumps(issue, default=str)[:2048],
            ))

        return results
