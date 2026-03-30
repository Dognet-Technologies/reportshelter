"""
ImmuniWeb parser — supports both XML and JSON formats.

ImmuniWeb XML:
  <Vulnerabilities>
    <Vulnerability>
      <ID>...</ID>
      <Name>...</Name>
      <Type>...</Type>
      <Risk>CRITICAL|HIGH|MEDIUM|LOW|INFO</Risk>
      <CVSSv3>score [vector]</CVSSv3>
      <CWE-ID>CWE-XXX</CWE-ID>
      <CVE-ID>CVE-XXXX-XXXXX</CVE-ID>
      <URL>...</URL>
      <Description>...</Description>
      <PoC>...</PoC>
      <Remediation>...</Remediation>
    </Vulnerability>
  </Vulnerabilities>

ImmuniWeb JSON:
  [{"Name":"...", "Risk":"...", "Type":"...", "Description":"...", ...}]
  or {"vulnerabilities": [...]}
"""

from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
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
    "informational": "info",
}

_CVSS_SCORE_RE = re.compile(r"^(\d+(?:\.\d+)?)")


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower().strip(), "info")


def _parse_cvss3(raw: str) -> tuple[float | None, str]:
    """Parse '9.8 [CVSS:3.0/...]' into (score, vector)."""
    if not raw:
        return None, ""
    m = _CVSS_SCORE_RE.match(raw.strip())
    score: float | None = None
    if m:
        try:
            score = float(m.group(1))
        except ValueError:
            pass
    vector_m = re.search(r"(CVSS:\d+\.\d+/[A-Z:/]+)", raw)
    vector = vector_m.group(1) if vector_m else ""
    return score, vector


class ImmuniWebParser(BaseParser):
    """Parser for ImmuniWeb XML and JSON vulnerability reports."""

    tool_name = "immuniweb"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        raw = file_obj.read()
        text = raw.decode("utf-8", errors="replace").lstrip()

        if text.startswith("{") or text.startswith("["):
            return self._parse_json(text)
        return self._parse_xml(raw)

    # ------------------------------------------------------------------
    def _parse_xml(self, raw: bytes) -> list[NormalizedVulnerability]:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid ImmuniWeb XML: {exc}") from exc

        results: list[NormalizedVulnerability] = []
        for vuln in root.iter("Vulnerability"):
            name = (vuln.findtext("Name") or "").strip() or "ImmuniWeb Finding"
            risk = _sev(vuln.findtext("Risk") or "")
            vuln_type = (vuln.findtext("Type") or "").strip()
            cwe = (vuln.findtext("CWE-ID") or "").strip()
            cve = (vuln.findtext("CVE-ID") or "").strip()
            url = (vuln.findtext("URL") or "").strip()
            description = (vuln.findtext("Description") or "").strip()
            poc = (vuln.findtext("PoC") or "").strip()[:1000]
            remediation = (vuln.findtext("Remediation") or "").strip()
            cvss_raw = (vuln.findtext("CVSSv3") or "").strip()
            cvss_score, cvss_vector = _parse_cvss3(cvss_raw)

            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or url
            port: int | None = parsed.port
            if port is None and parsed.scheme:
                port = 443 if parsed.scheme == "https" else 80

            evidence = f"URL: {url}"
            if poc:
                evidence += f"\n\nProof of Concept:\n{poc}"

            results.append(NormalizedVulnerability(
                title=name,
                description=description,
                remediation=remediation,
                affected_host=host,
                affected_port=port,
                cve_id=[cve] if cve and cve.startswith("CVE-") else [],
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                risk_level=risk,
                category=cwe or vuln_type,
                evidence_code=evidence[:4096],
                source="immuniweb",
                raw_output=ET.tostring(vuln, encoding="unicode")[:2048],
            ))

        return results

    # ------------------------------------------------------------------
    def _parse_json(self, text: str) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid ImmuniWeb JSON: {exc}") from exc

        if isinstance(data, dict):
            items = data.get("vulnerabilities") or data.get("Vulnerabilities") or [data]
        elif isinstance(data, list):
            items = data
        else:
            raise ParserError("Unexpected ImmuniWeb JSON structure.")

        results: list[NormalizedVulnerability] = []
        for item in items:
            if not isinstance(item, dict):
                continue

            name = item.get("Name") or item.get("name") or "ImmuniWeb Finding"
            risk = _sev(item.get("Risk") or item.get("risk") or "")
            description = item.get("Description") or item.get("description") or ""
            remediation = item.get("Remediation") or item.get("remediation") or ""
            url = item.get("URL") or item.get("url") or ""
            cwe = item.get("CWE-ID") or item.get("cwe") or ""
            cve = item.get("CVE-ID") or item.get("cve") or ""

            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or url

            results.append(NormalizedVulnerability(
                title=name,
                description=description,
                remediation=remediation,
                affected_host=host,
                cve_id=[cve] if cve and cve.startswith("CVE-") else [],
                risk_level=risk,
                category=cwe,
                evidence_code=f"URL: {url}",
                source="immuniweb",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return results
