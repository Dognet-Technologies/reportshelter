"""
Qualys Web Application Scanner XML parser.

<WAS_SCAN_REPORT>
  <RESULTS>
    <VULNERABILITY_LIST>
      <VULNERABILITY>
        <QID>...</QID>
        <URL>...</URL>
        <TITLE>...</TITLE>
        <SEVERITY>1-5</SEVERITY>
        <CATEGORY>...</CATEGORY>
        <CWE>CWE-XXX</CWE>
        <CVE_LIST><CVE><ID>CVE-...</ID></CVE></CVE_LIST>
        <DESCRIPTION><![CDATA[...]]></DESCRIPTION>
        <SOLUTION><![CDATA[...]]></SOLUTION>
        <CVSS3_BASE>...</CVSS3_BASE>
      </VULNERABILITY>
    </VULNERABILITY_LIST>
  </RESULTS>
</WAS_SCAN_REPORT>

Severity 1=info, 2=low, 3=medium, 4=high, 5=critical.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import IO
from urllib.parse import urlparse

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_MAP = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}


def _sev(val: str) -> str:
    try:
        return _SEV_MAP.get(int(val), "info")
    except (TypeError, ValueError):
        return "info"


def _text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return (el.text or "").strip()


class QualysWebAppParser(BaseParser):
    """Parser for Qualys WAS (Web Application Scanner) XML reports."""

    tool_name = "qualys_webapp"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            root = ET.fromstring(file_obj.read())
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Qualys WAS XML: {exc}") from exc

        if "WAS_SCAN_REPORT" not in root.tag and root.tag != "WAS_SCAN_REPORT":
            # Try parsing from content regardless
            pass

        results: list[NormalizedVulnerability] = []

        for vuln in root.iter("VULNERABILITY"):
            title = _text(vuln.find("TITLE")) or _text(vuln.find("NAME")) or "Qualys WAS Finding"
            url = _text(vuln.find("URL"))
            severity_raw = _text(vuln.find("SEVERITY")) or _text(vuln.find("LEVEL"))
            severity = _sev(severity_raw)
            category = _text(vuln.find("CATEGORY")) or _text(vuln.find("TYPE"))
            cwe = _text(vuln.find("CWE")) or ""
            description = _text(vuln.find("DESCRIPTION")) or _text(vuln.find("DETAIL"))
            solution = _text(vuln.find("SOLUTION")) or _text(vuln.find("REMEDIATION"))
            cvss3 = _text(vuln.find("CVSS3_BASE")) or _text(vuln.find("CVSS_BASE"))

            cvss_score: float | None = None
            try:
                cvss_score = float(cvss3) if cvss3 else None
            except ValueError:
                pass

            # CVE IDs
            cve_list: list[str] = []
            for cve_el in vuln.iter("ID"):
                val = (cve_el.text or "").strip()
                if val.startswith("CVE-"):
                    cve_list.append(val)
            # Also check CVE text nodes
            for cve_el in vuln.iter("CVE"):
                val = (cve_el.text or "").strip()
                if val.startswith("CVE-"):
                    cve_list.append(val)

            # Host from URL
            host = ""
            port: int | None = None
            if url:
                parsed = urlparse(url)
                host = parsed.hostname or url
                port = parsed.port
                if port is None and parsed.scheme:
                    port = 443 if parsed.scheme == "https" else 80

            evidence = f"URL: {url}\nQID: {_text(vuln.find('QID'))}"
            if category:
                evidence += f"\nCategory: {category}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=solution,
                affected_host=host,
                affected_port=port,
                cve_id=cve_list,
                cvss_score=cvss_score,
                risk_level=severity,
                category=cwe or category,
                evidence_code=evidence[:4096],
                source="qualys_webapp",
                raw_output=ET.tostring(vuln, encoding="unicode")[:2048],
            ))

        return results
