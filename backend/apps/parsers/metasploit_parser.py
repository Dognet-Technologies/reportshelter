"""
Metasploit XML parser.
Parses output from: db_export -f xml output.xml
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError


class MetasploitParser(BaseParser):
    """Parser for Metasploit db_export XML format."""

    tool_name = "metasploit"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            tree = ET.parse(file_obj)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Metasploit XML: {exc}") from exc

        root = tree.getroot()
        if root.tag != "MetasploitV5":
            raise ParserError("Not a valid Metasploit XML export (root must be 'MetasploitV5').")

        results: list[NormalizedVulnerability] = []

        # Map host IDs to addresses for cross-reference
        host_map: dict[str, str] = {}
        for host in root.findall(".//host"):
            host_id = host.get("id", "")
            address = host.findtext("address", "")
            if host_id and address:
                host_map[host_id] = address

        # Parse vulnerabilities
        for vuln in root.findall(".//vuln"):
            name = vuln.findtext("name", "").strip()
            info = vuln.findtext("info", "").strip()
            refs_elem = vuln.find("refs")
            host_id = vuln.get("host_id", "")
            port_raw = vuln.findtext("port", "")
            proto = vuln.findtext("proto", "tcp")

            if not name:
                continue

            host_addr = host_map.get(host_id, "")

            cve_ids: list[str] = []
            cvss_score = None
            refs: list[str] = []

            if refs_elem is not None:
                for ref in refs_elem.findall("ref"):
                    ref_name = ref.findtext("name", "")
                    if ref_name.startswith("CVE-"):
                        cve_ids.append(ref_name)
                    elif ref_name.startswith("CVSS-"):
                        try:
                            cvss_score = float(ref_name.split("-")[1])
                        except (IndexError, ValueError):
                            pass
                    refs.append(ref_name)

            risk_level = self._assess_risk(cvss_score, name, info)

            # Parse port to int
            port_int: int | None = None
            try:
                port_int = int(port_raw)
            except (ValueError, TypeError):
                pass

            evidence = f"Info: {info}"
            if refs:
                evidence += f"\nReferences: {', '.join(refs[:10])}"
            if port_raw:
                evidence += f"\nPort: {port_raw}/{proto}"

            results.append(NormalizedVulnerability(
                title=f"MSF: {name}",
                description=info or name,
                affected_host=host_addr,
                affected_port=port_int,
                affected_service=proto,
                cve_id=cve_ids,
                cvss_score=cvss_score,
                risk_level=risk_level,
                evidence_code=evidence[:4096],
                source=self.tool_name,
                raw_output=ET.tostring(vuln, encoding="unicode")[:4096],
            ))

        # Also parse notes as informational findings
        for note in root.findall(".//note"):
            ntype = note.findtext("ntype", "").strip()
            data = note.findtext("data", "").strip()
            host_id = note.get("host_id", "")

            if not ntype or not data or ntype in ("host.os.session_fingerprint",):
                continue

            host_addr = host_map.get(host_id, "")

            results.append(NormalizedVulnerability(
                title=f"MSF Note: {ntype}",
                description=data[:512],
                affected_host=host_addr,
                risk_level="info",
                evidence_code=data[:2048],
                source=self.tool_name,
                raw_output=ET.tostring(note, encoding="unicode")[:2048],
            ))

        return results

    def _assess_risk(self, cvss_score: float | None, name: str, info: str) -> str:
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return "critical"
            if cvss_score >= 7.0:
                return "high"
            if cvss_score >= 4.0:
                return "medium"
            if cvss_score > 0.0:
                return "low"
        combined = (name + " " + info).lower()
        if any(kw in combined for kw in ("critical", "rce", "remote code", "privilege escalation")):
            return "high"
        if any(kw in combined for kw in ("sql injection", "xss", "injection")):
            return "medium"
        return "low"
