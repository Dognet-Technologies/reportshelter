"""
Burp Suite XML parser.
Parses the XML export from Burp Suite Pro (Issue Activity export).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from html import unescape
from typing import IO
from urllib.parse import urlparse

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError


class BurpParser(BaseParser):
    """Parser for Burp Suite XML issue export."""

    tool_name = "burp"

    SEVERITY_MAP = {
        "high": "high",
        "medium": "medium",
        "low": "low",
        "information": "info",
        "informational": "info",
        "false positive": "info",
    }

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            tree = ET.parse(file_obj)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Burp XML: {exc}") from exc

        root = tree.getroot()
        if root.tag != "issues":
            raise ParserError("Not a valid Burp Suite XML export (root must be 'issues').")

        results: list[NormalizedVulnerability] = []

        for issue in root.findall("issue"):
            name = issue.findtext("name", "").strip()
            host_elem = issue.find("host")
            url_str = issue.findtext("location", "").strip()
            severity = issue.findtext("severity", "information").strip().lower()
            confidence = issue.findtext("confidence", "").strip()
            issue_bg = self._clean_html(issue.findtext("issueBackground", ""))
            remediation_bg = self._clean_html(issue.findtext("remediationBackground", ""))
            issue_detail = self._clean_html(issue.findtext("issueDetail", ""))
            request = issue.findtext(".//request", "")
            response = issue.findtext(".//response", "")

            if not name:
                continue

            # Parse host and port from host element or URL
            host = ""
            port = "80"
            if host_elem is not None:
                host = host_elem.get("ip", host_elem.text or "")
                port_attr = host_elem.get("port", "")
                if port_attr:
                    port = port_attr
            elif url_str:
                parsed = urlparse(url_str)
                host = parsed.hostname or ""
                port = str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80")

            cve_id = self._extract_cve(issue_bg + " " + remediation_bg)
            risk_level = self.SEVERITY_MAP.get(severity, "info")

            evidence_parts = [f"URL: {url_str}", f"Confidence: {confidence}"]
            if issue_detail:
                evidence_parts.append(f"Detail:\n{issue_detail}")
            if request:
                evidence_parts.append(f"Request:\n{request[:2000]}")

            results.append(NormalizedVulnerability(
                title=f"Burp: {name}",
                description=issue_bg or issue_detail,
                remediation=remediation_bg,
                affected_host=host,
                affected_port=port,
                affected_service="http",
                cve_id=cve_id,
                risk_level=risk_level,
                evidence_code="\n\n".join(evidence_parts)[:8192],
                source=self.tool_name,
                raw_output=ET.tostring(issue, encoding="unicode")[:4096],
            ))

        return results

    def _clean_html(self, text: str) -> str:
        """Strip HTML tags and decode entities."""
        if not text:
            return ""
        text = re.sub(r"<[^>]+>", " ", text)
        return unescape(text).strip()

    def _extract_cve(self, text: str) -> str:
        match = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
        return match.group(0).upper() if match else ""
