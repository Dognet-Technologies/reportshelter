"""
Acunetix parser — supports both Acunetix Classic XML and Acunetix 360 JSON.

Acunetix Classic XML (acunetix.com scanner):
  root: <ScanGroup><Scan><ReportItems><ReportItem>
    <Name>         — vuln name
    <Severity>     — high|medium|low|informational
    <Description>
    <Recommendation>
    <CWEList><CWE id="...">
    <References><Reference><URL>

Acunetix 360 JSON (acunetix360.com / invicti):
  root: {Target: {Url}, Vulnerabilities: [...]}
  Each vuln:
    Name                           — vuln name
    Classification.Cvss.BaseScore.Value  — CVSS score
    Classification.Cvss.Vector
    Classification.Cwe             — CWE ID string
    Classification.Owasp           — OWASP category
    Description                    — HTML description
    RemedialProcedure              — HTML remediation
    Severity  (0=info,1=low,2=medium,3=high,4=critical)
    Url / AffectedUrls[]
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

_SEV_XML = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "information": "info",
}

_SEV_INT = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

_HTML_TAG = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    return _HTML_TAG.sub("", text or "").strip()


def _sev_xml(raw: str) -> str:
    return _SEV_XML.get((raw or "").lower().strip(), "info")


def _sev_int(val) -> str:
    try:
        return _SEV_INT.get(int(val), "info")
    except (TypeError, ValueError):
        return _sev_xml(str(val))


class AcunetixParser(BaseParser):
    """Parser for Acunetix Classic XML and Acunetix 360 JSON reports."""

    tool_name = "acunetix"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        raw = file_obj.read()
        text = raw.decode("utf-8", errors="replace").lstrip()

        if text.startswith("{") or text.startswith("["):
            return self._parse_json(text)
        return self._parse_xml(raw)

    # ------------------------------------------------------------------
    # Acunetix 360 JSON
    # ------------------------------------------------------------------
    def _parse_json(self, text: str) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Acunetix JSON: {exc}") from exc

        target_url = (data.get("Target") or {}).get("Url") or ""
        vulns = data.get("Vulnerabilities") or []

        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port: int | None = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80

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
            if cwe and not cwe.startswith("CWE-"):
                cwe = f"CWE-{cwe}"

            severity_raw = v.get("Severity")
            severity = _sev_int(severity_raw)

            name = v.get("Name") or v.get("Title") or "Acunetix Finding"
            description = _strip_html(v.get("Description") or "")
            remediation = _strip_html(v.get("RemedialProcedure") or v.get("Recommendation") or "")

            url = v.get("Url") or (
                (v.get("AffectedUrls") or [{}])[0].get("Url", "") if v.get("AffectedUrls") else ""
            ) or target_url

            evidence = f"URL: {url}\nCWE: {cwe}\nOWASP: {cls.get('Owasp', '')}"

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
                evidence_code=evidence[:4096],
                source="acunetix",
                raw_output=json.dumps(v, default=str)[:2048],
            ))

        return results

    # ------------------------------------------------------------------
    # Acunetix Classic XML
    # ------------------------------------------------------------------
    def _parse_xml(self, raw: bytes) -> list[NormalizedVulnerability]:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Acunetix XML: {exc}") from exc

        results: list[NormalizedVulnerability] = []

        for scan in root.iter("Scan"):
            start_url = (scan.findtext("StartURL") or "").strip()
            from urllib.parse import urlparse
            parsed = urlparse(start_url)
            host = parsed.hostname or start_url
            port: int | None = parsed.port
            if port is None and parsed.scheme:
                port = 443 if parsed.scheme == "https" else 80

            for item in scan.iter("ReportItem"):
                name = (item.findtext("Name") or "").strip() or "Acunetix Finding"
                severity = _sev_xml(item.findtext("Severity") or "")
                description = _strip_html(
                    item.findtext("Description") or item.findtext("Details") or ""
                )
                recommendation = _strip_html(
                    item.findtext("Recommendation") or item.findtext("Solution") or ""
                )
                affects = (item.findtext("Affects") or "").strip()

                # CWE
                cwe_ids = [
                    f"CWE-{c.get('id')}"
                    for c in item.iter("CWE")
                    if c.get("id")
                ]
                cwe = cwe_ids[0] if cwe_ids else ""

                # CVE from References
                cve_list: list[str] = []
                for ref in item.iter("URL"):
                    url_text = ref.text or ""
                    m = re.search(r"CVE-\d{4}-\d+", url_text)
                    if m:
                        cve_list.append(m.group())

                evidence = f"Affects: {affects}"
                if affects:
                    evidence += f"\nURL: {start_url}{affects}"

                results.append(NormalizedVulnerability(
                    title=name,
                    description=description,
                    remediation=recommendation,
                    affected_host=host,
                    affected_port=port,
                    cve_id=cve_list,
                    risk_level=severity,
                    category=cwe,
                    evidence_code=evidence[:4096],
                    source="acunetix",
                    raw_output=ET.tostring(item, encoding="unicode")[:2048],
                ))

        return results
