"""
Qualys Infrastructure Scanner parser — supports both CSV and XML formats.

CSV format (columns, first row header):
  IP, Network, DNS, NetBIOS, Tracking Method, OS, IP Status,
  QID, Title, Vuln Status, Type, Severity, Port, Protocol,
  FQDN, SSL, First Detected, Last Detected, Times Detected,
  Date Last Fixed, CVE ID, Vendor Reference, Bugtraq ID,
  CVSS3, CVSS3 Base, CVSS3 Temporal,
  Threat, Impact, Solution, Exploitability, Associated Malware,
  PCI Vuln, Ticket State, Instance, OS CPE, Category, Associated Tags
Severity: 1=info, 2=low, 3=medium, 4=high, 5=critical.

XML format (ASSET_DATA_REPORT):
  HOST_LIST/HOST — per-host findings (IP, DNS, VULN_INFO_LIST)
  GLOSSARY/VULN_DETAILS_LIST — QID → title/severity/threat/solution/CVE lookup
"""

from __future__ import annotations

import csv
import io
import logging
from typing import IO
from xml.etree import ElementTree

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "1": "info",
    "2": "low",
    "3": "medium",
    "4": "high",
    "5": "critical",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").strip(), "info")


def _float_or_none(val: str) -> float | None:
    try:
        return float(val.strip()) if val and val.strip() else None
    except ValueError:
        return None


def _int_or_none(val: str) -> int | None:
    try:
        return int(val.strip()) if val and val.strip() else None
    except ValueError:
        return None


class QualysParser(BaseParser):
    """Parser for Qualys Infrastructure Scanner CSV and XML exports."""

    tool_name = "qualys"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        raw = file_obj.read()
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            raise ParserError(f"Cannot decode Qualys file: {exc}") from exc

        # Detect XML (ASSET_DATA_REPORT) vs CSV by checking the first non-whitespace bytes.
        stripped = text.lstrip()
        if stripped.startswith("<?xml") or stripped.startswith("<ASSET_DATA_REPORT"):
            return self._parse_xml(stripped)

        # Skip comment lines at the top (Qualys sometimes prepends metadata)
        lines = text.splitlines()
        header_idx = 0
        for i, line in enumerate(lines):
            if line.strip().startswith('"IP"') or line.strip().startswith("IP,"):
                header_idx = i
                break

        csv_text = "\n".join(lines[header_idx:])
        if not csv_text.strip():
            raise ParserError("Qualys CSV is empty or has no data rows.")

        try:
            reader = csv.DictReader(io.StringIO(csv_text), quotechar='"')
        except Exception as exc:
            raise ParserError(f"Cannot parse Qualys CSV: {exc}") from exc

        results: list[NormalizedVulnerability] = []

        for row in reader:
            # Strip BOM and whitespace from keys
            row = {k.strip().lstrip("\ufeff").strip('"'): v for k, v in row.items()}

            vuln_status = (row.get("Vuln Status") or "").strip()
            if vuln_status.upper() == "FIXED":
                continue

            ip = (row.get("IP") or "").strip()
            dns = (row.get("DNS") or row.get("FQDN") or "").strip()
            host = dns or ip

            title = (row.get("Title") or row.get("Name") or "Qualys Finding").strip()
            severity = _sev(row.get("Severity") or "")
            port_raw = (row.get("Port") or "").strip()
            protocol = (row.get("Protocol") or "tcp").strip().lower()
            port = _int_or_none(port_raw)

            cve_raw = (row.get("CVE ID") or row.get("CVE") or "").strip()
            cve_list = [c.strip() for c in cve_raw.split(",") if c.strip().startswith("CVE-")]

            cvss3_base = _float_or_none(
                (row.get("CVSS3 Base") or row.get("CVSS3") or "").split("(")[0].strip()
            )

            threat = (row.get("Threat") or "").strip()
            impact = (row.get("Impact") or "").strip()
            solution = (row.get("Solution") or "").strip()

            description = threat
            if impact:
                description += f"\n\nImpact: {impact}"

            evidence = f"IP: {ip}\nDNS: {dns}\nPort: {port}/{protocol}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=solution,
                affected_host=host,
                affected_ip=ip,
                affected_port=port,
                affected_protocol=protocol,
                cve_id=cve_list,
                cvss_score=cvss3_base,
                risk_level=severity,
                evidence_code=evidence[:4096],
                source="qualys",
                raw_output=str(dict(list(row.items())[:20]))[:2048],
            ))

        return results

    # ------------------------------------------------------------------
    # XML (ASSET_DATA_REPORT) support
    # ------------------------------------------------------------------

    def _parse_xml(self, text: str) -> list[NormalizedVulnerability]:
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError as exc:
            raise ParserError(f"Invalid Qualys XML: {exc}") from exc

        # Build QID → details lookup from GLOSSARY section
        glossary: dict[str, dict] = {}
        for vd in root.findall(".//GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS"):
            qid_el = vd.find("QID")
            if qid_el is None:
                continue
            qid = (qid_el.text or "").strip()
            if not qid:
                continue
            cve_list = [
                el.text.strip()
                for el in vd.findall(".//CVE_ID_LIST/CVE_ID/ID")
                if el.text and el.text.strip().startswith("CVE-")
            ]
            glossary[qid] = {
                "title": (vd.findtext("TITLE") or "").strip(),
                "severity": (vd.findtext("SEVERITY") or "").strip(),
                "threat": (vd.findtext("THREAT") or "").strip(),
                "impact": (vd.findtext("IMPACT") or "").strip(),
                "solution": (vd.findtext("SOLUTION") or "").strip(),
                "category": (vd.findtext("CATEGORY") or "").strip(),
                "cve_list": cve_list,
            }

        results: list[NormalizedVulnerability] = []

        for host_el in root.findall(".//HOST_LIST/HOST"):
            ip = (host_el.findtext("IP") or "").strip()
            dns = (host_el.findtext("DNS") or "").strip()
            host = dns or ip

            for vi in host_el.findall(".//VULN_INFO_LIST/VULN_INFO"):
                qid_el = vi.find("QID")
                if qid_el is None:
                    continue
                qid = (qid_el.text or "").strip()
                details = glossary.get(qid, {})

                title = details.get("title") or f"QID {qid}"
                severity_raw = details.get("severity") or ""
                severity = _sev(severity_raw)
                threat = details.get("threat") or ""
                impact = details.get("impact") or ""
                solution = details.get("solution") or ""
                category = details.get("category") or ""
                cve_list = details.get("cve_list") or []

                port_raw = (vi.findtext("PORT") or "").strip()
                protocol = (vi.findtext("PROTOCOL") or "tcp").strip().lower()
                port = _int_or_none(port_raw)
                result_text = (vi.findtext("RESULT") or "")[:512]

                description = threat
                if impact:
                    description += f"\n\nImpact: {impact}"

                evidence = f"IP: {ip}\nDNS: {dns}"
                if port:
                    evidence += f"\nPort: {port}/{protocol}"
                if result_text:
                    evidence += f"\nResult: {result_text}"

                results.append(NormalizedVulnerability(
                    title=title,
                    description=description,
                    remediation=solution,
                    affected_host=host,
                    affected_ip=ip,
                    affected_port=port,
                    affected_protocol=protocol,
                    cve_id=cve_list,
                    risk_level=severity,
                    category=category,
                    evidence_code=evidence[:4096],
                    source="qualys",
                    raw_output=f"QID:{qid} IP:{ip}"[:2048],
                ))

        return results
