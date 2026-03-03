"""
OWASP ZAP parser.
Supports both XML and JSON report formats from ZAP.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError


class ZAPParser(BaseParser):
    """
    Parser for OWASP ZAP output.
    Auto-detects XML vs JSON format from the file content.
    """

    tool_name = "zap"

    RISK_MAP = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
    }

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        raw = file_obj.read()

        # Auto-detect format
        stripped = raw.lstrip()
        if stripped.startswith(b"{") or stripped.startswith(b"["):
            return self._parse_json(raw)
        else:
            return self._parse_xml(raw)

    # ------------------------------------------------------------------
    # XML format
    # ------------------------------------------------------------------

    def _parse_xml(self, raw: bytes) -> list[NormalizedVulnerability]:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid ZAP XML: {exc}") from exc

        results: list[NormalizedVulnerability] = []

        for site in root.findall(".//site"):
            host = site.get("host", "")
            port = site.get("port", "80")

            for alert in site.findall(".//alertitem"):
                name = alert.findtext("alert", "").strip()
                desc = alert.findtext("desc", "").strip()
                solution = alert.findtext("solution", "").strip()
                risk_code = alert.findtext("riskcode", "0").strip()
                confidence = alert.findtext("confidence", "").strip()
                cwe_id = alert.findtext("cweid", "").strip()
                wascid = alert.findtext("wascid", "").strip()
                evidence = alert.findtext("evidence", "").strip()
                reference = alert.findtext("reference", "").strip()

                cve_id = self._extract_cve(desc + " " + reference)
                risk_level = self.RISK_MAP.get(risk_code, "info")

                evidence_text = ""
                if evidence:
                    evidence_text = f"Evidence: {evidence}\n"
                if cwe_id:
                    evidence_text += f"CWE: {cwe_id}\n"
                if confidence:
                    evidence_text += f"Confidence: {confidence}"

                # Collect all URIs for this alert
                uris = [uri.findtext("uri", "") for uri in alert.findall(".//uri")]
                if uris:
                    evidence_text += f"\nURLs:\n" + "\n".join(uris[:10])

                results.append(NormalizedVulnerability(
                    title=f"ZAP: {name}",
                    description=desc,
                    remediation=solution,
                    affected_host=host,
                    affected_port=port,
                    affected_service="http",
                    cve_id=cve_id,
                    risk_level=risk_level,
                    evidence_code=evidence_text[:4096],
                    source=self.tool_name,
                    raw_output=ET.tostring(alert, encoding="unicode")[:4096],
                ))

        return results

    # ------------------------------------------------------------------
    # JSON format (ZAP 2.10+)
    # ------------------------------------------------------------------

    def _parse_json(self, raw: bytes) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid ZAP JSON: {exc}") from exc

        results: list[NormalizedVulnerability] = []
        sites = data if isinstance(data, list) else data.get("site", [])

        for site in sites:
            host = site.get("@host", "")
            port = str(site.get("@port", "80"))
            alerts = site.get("alerts", [])

            for alert in alerts:
                name = alert.get("alert", "").strip()
                desc = alert.get("desc", "").strip()
                solution = alert.get("solution", "").strip()
                risk_code = str(alert.get("riskcode", "0"))
                confidence = str(alert.get("confidence", ""))
                evidence = alert.get("evidence", "").strip()
                reference = alert.get("reference", "").strip()
                cwe_id = str(alert.get("cweid", ""))

                cve_id = self._extract_cve(desc + " " + reference)
                risk_level = self.RISK_MAP.get(risk_code, "info")

                evidence_text = ""
                if evidence:
                    evidence_text += f"Evidence: {evidence}\n"
                if cwe_id:
                    evidence_text += f"CWE: {cwe_id}\n"
                if confidence:
                    evidence_text += f"Confidence: {confidence}"

                instances = alert.get("instances", [])
                if instances:
                    uris = [i.get("uri", "") for i in instances[:10]]
                    evidence_text += "\nURLs:\n" + "\n".join(uris)

                results.append(NormalizedVulnerability(
                    title=f"ZAP: {name}",
                    description=desc,
                    remediation=solution,
                    affected_host=host,
                    affected_port=port,
                    affected_service="http",
                    cve_id=cve_id,
                    risk_level=risk_level,
                    evidence_code=evidence_text[:4096],
                    source=self.tool_name,
                    raw_output=json.dumps(alert, indent=2)[:4096],
                ))

        return results

    def _extract_cve(self, text: str) -> str:
        match = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
        return match.group(0).upper() if match else ""
