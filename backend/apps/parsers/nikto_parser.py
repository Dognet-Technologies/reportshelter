"""
Nikto XML parser.
Parses output from: nikto -h <target> -Format xml -output output.xml
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError


class NiktoParser(BaseParser):
    """Parser for Nikto XML output."""

    tool_name = "nikto"

    # Map Nikto OSVDB IDs to rough severity levels (heuristic)
    HIGH_SEVERITY_KEYWORDS = ["sql injection", "xss", "rce", "command execution", "directory traversal", "arbitrary"]
    MEDIUM_SEVERITY_KEYWORDS = ["outdated", "deprecated", "enabled", "exposed", "information disclosure"]

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            tree = ET.parse(file_obj)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Nikto XML: {exc}") from exc

        root = tree.getroot()
        # Nikto XML root can be <niktoscan> or <nikto>
        if root.tag not in ("niktoscan", "nikto"):
            raise ParserError("Not a valid Nikto XML file.")

        results: list[NormalizedVulnerability] = []

        for scan_detail in root.iter("scandetails"):
            target_ip = scan_detail.get("targetip", "")
            target_port = scan_detail.get("targetport", "80")

            for item in scan_detail.findall("item"):
                description = item.findtext("description", "").strip()
                uri = item.findtext("uri", "").strip()
                osvdb = item.get("osvdbid", "")
                method = item.get("method", "GET")

                if not description:
                    continue

                cve_id = self._extract_cve(description)
                risk_level = self._assess_risk(description, osvdb)

                evidence = f"URI: {uri}\nMethod: {method}\nDescription: {description}"
                if osvdb:
                    evidence += f"\nOSVDB: {osvdb}"

                results.append(NormalizedVulnerability(
                    title=f"Nikto: {description[:120]}",
                    description=description,
                    affected_host=target_ip,
                    affected_port=target_port,
                    affected_service="http",
                    cve_id=cve_id,
                    risk_level=risk_level,
                    evidence_code=evidence,
                    source=self.tool_name,
                    raw_output=ET.tostring(item, encoding="unicode"),
                ))

        return results

    def _extract_cve(self, text: str) -> str:
        match = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
        return match.group(0).upper() if match else ""

    def _assess_risk(self, description: str, osvdb: str) -> str:
        desc_lower = description.lower()
        for kw in self.HIGH_SEVERITY_KEYWORDS:
            if kw in desc_lower:
                return "high"
        for kw in self.MEDIUM_SEVERITY_KEYWORDS:
            if kw in desc_lower:
                return "medium"
        return "low"
