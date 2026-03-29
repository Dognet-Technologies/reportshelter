"""
Nikto XML parser.
Parses output from: nikto -h <target> -Format xml -output output.xml

Handles two common quirks of Nikto XML output:
  1. Multiple XML documents concatenated in one file (nikto -h multiple hosts)
  2. Content after the closing tag ("junk after document element")
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

    HIGH_SEVERITY_KEYWORDS = [
        "sql injection", "xss", "rce", "command execution",
        "directory traversal", "arbitrary", "remote code",
    ]
    MEDIUM_SEVERITY_KEYWORDS = [
        "outdated", "deprecated", "enabled", "exposed",
        "information disclosure", "misconfiguration",
    ]

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        raw = file_obj.read()

        roots = self._parse_xml_tolerant(raw)
        if not roots:
            raise ParserError("Could not parse Nikto XML — no valid XML document found.")

        results: list[NormalizedVulnerability] = []
        for root in roots:
            results.extend(self._extract_from_root(root))
        return results

    # ------------------------------------------------------------------
    # Tolerant XML parsing
    # ------------------------------------------------------------------

    def _parse_xml_tolerant(self, raw: bytes) -> list[ET.Element]:
        """
        Try several strategies to parse Nikto XML, which is often malformed:
          1. Direct parse (valid XML)
          2. Wrap all content in a <niktoroot> tag (handles multiple documents)
          3. Extract the first complete document only
        """
        # Strategy 1: parse as-is
        try:
            root = ET.fromstring(raw)
            return [root]
        except ET.ParseError:
            pass

        # Strategy 2: wrap in a synthetic root element
        try:
            # Strip any leading XML declaration to avoid duplicates after wrapping
            content = re.sub(rb'<\?xml[^?]*\?>', b'', raw).strip()
            wrapped = b'<niktoroot>' + content + b'</niktoroot>'
            root = ET.fromstring(wrapped)
            return [root]
        except ET.ParseError:
            pass

        # Strategy 3: extract the first closing tag position and parse up to it
        text = raw.decode("utf-8", errors="replace")
        for close_tag in ("</niktoscan>", "</nikto>"):
            pos = text.find(close_tag)
            if pos != -1:
                chunk = text[: pos + len(close_tag)]
                try:
                    root = ET.fromstring(chunk.encode("utf-8"))
                    return [root]
                except ET.ParseError:
                    continue

        return []

    # ------------------------------------------------------------------
    # Extraction
    # ------------------------------------------------------------------

    def _extract_from_root(self, root: ET.Element) -> list[NormalizedVulnerability]:
        results: list[NormalizedVulnerability] = []

        for scan_detail in root.iter("scandetails"):
            target_ip = scan_detail.get("targetip", "")
            target_port = scan_detail.get("targetport", "80")

            for item in scan_detail.findall("item"):
                description = (item.findtext("description") or "").strip()
                uri = (item.findtext("uri") or "").strip()
                osvdb = item.get("osvdbid", "")
                method = item.get("method", "GET")

                if not description:
                    continue

                cve_str = self._extract_cve(description)
                risk_level = self._assess_risk(description, osvdb)

                evidence = f"URI: {uri}\nMethod: {method}\nDescription: {description}"
                if osvdb:
                    evidence += f"\nOSVDB: {osvdb}"

                # Parse port to int
                port_int: int | None = None
                try:
                    port_int = int(target_port)
                except (ValueError, TypeError):
                    pass

                results.append(NormalizedVulnerability(
                    title=f"Nikto: {description[:120]}",
                    description=description,
                    affected_host=target_ip,
                    affected_port=port_int,
                    affected_service="http",
                    cve_id=[cve_str] if cve_str else [],
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
