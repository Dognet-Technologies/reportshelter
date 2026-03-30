"""
Sysdig Reports CSV/JSON parser.

Sysdig exports vulnerability reports in two formats:

CSV columns:
  Vulnerability ID, Severity, Package name, Package version,
  Package type, Package path, Image, OS Name,
  CVSS version, CVSS score, CVSS vector, Vuln link,
  Vuln Publish date, Vuln Fix date, Fix version,
  Public Exploit, Registry name, Registry image repository,
  Image ID, Package suggested fix, Risk accepted

JSON format:
  {"results": [{"vulnerabilities": [...], "metadata": {...}}]}
  or {"vulnerabilities": [...]}
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "negligible": "info",
    "unknown": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower().strip(), "info")


def _float_or_none(val: str) -> float | None:
    try:
        return float((val or "").strip()) if val and val.strip() else None
    except ValueError:
        return None


class SysdigParser(BaseParser):
    """Parser for Sysdig vulnerability report CSV and JSON exports."""

    tool_name = "sysdig"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        raw = file_obj.read()
        text = raw.decode("utf-8", errors="replace").lstrip()

        if text.startswith("{") or text.startswith("["):
            return self._parse_json(text)
        return self._parse_csv(text)

    # ------------------------------------------------------------------
    def _parse_csv(self, text: str) -> list[NormalizedVulnerability]:
        lines = text.splitlines()
        if not lines:
            raise ParserError("Sysdig CSV is empty.")

        # Find header line
        header_idx = 0
        for i, line in enumerate(lines):
            lower = line.lower()
            if "vulnerability id" in lower or "severity" in lower:
                header_idx = i
                break

        csv_text = "\n".join(lines[header_idx:])
        try:
            reader = csv.DictReader(io.StringIO(csv_text))
        except Exception as exc:
            raise ParserError(f"Cannot parse Sysdig CSV: {exc}") from exc

        results: list[NormalizedVulnerability] = []
        for row in reader:
            row = {k.strip().lstrip("\ufeff"): v for k, v in row.items() if k}

            cve_id = (row.get("Vulnerability ID") or row.get("CVE") or "").strip()
            if not cve_id:
                continue

            severity = _sev(row.get("Severity") or "")
            pkg_name = (row.get("Package name") or "").strip()
            pkg_version = (row.get("Package version") or "").strip()
            pkg_type = (row.get("Package type") or "").strip()
            image = (row.get("Image") or "").strip()
            os_name = (row.get("OS Name") or "").strip()
            cvss_score = _float_or_none(row.get("CVSS score") or "")
            cvss_vector = (row.get("CVSS vector") or "").strip()
            fix_version = (row.get("Fix version") or row.get("Package suggested fix") or "").strip()
            vuln_link = (row.get("Vuln link") or "").strip()

            title = f"{cve_id} in {pkg_name}" if pkg_name else cve_id
            description = (
                f"CVE: {cve_id}\nPackage: {pkg_name} {pkg_version} ({pkg_type})\n"
                f"Image: {image}\nOS: {os_name}"
            )
            remediation = f"Upgrade {pkg_name} to {fix_version}." if fix_version else ""
            if vuln_link:
                description += f"\nLink: {vuln_link}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=remediation,
                affected_host=image or os_name,
                cve_id=[cve_id] if cve_id.startswith("CVE-") else [],
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                risk_level=severity,
                source="sysdig",
                raw_output=str(dict(list(row.items())[:15]))[:2048],
            ))

        return results

    # ------------------------------------------------------------------
    def _parse_json(self, text: str) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Sysdig JSON: {exc}") from exc

        if isinstance(data, list):
            vuln_list = data
        elif isinstance(data, dict):
            vuln_list = (
                data.get("vulnerabilities")
                or data.get("results")
                or []
            )
        else:
            raise ParserError("Unexpected Sysdig JSON structure.")

        results: list[NormalizedVulnerability] = []
        for item in vuln_list:
            if not isinstance(item, dict):
                continue

            cve_id = (item.get("vuln") or item.get("cve") or item.get("id") or "").strip()
            severity = _sev(item.get("severity") or "")
            pkg_name = item.get("packageName") or item.get("package") or ""
            pkg_version = item.get("packageVersion") or item.get("version") or ""
            cvss_score = item.get("cvssScore") or item.get("score")
            fix_version = item.get("fixedVersion") or item.get("fix") or ""
            description = item.get("description") or f"CVE: {cve_id} in {pkg_name}"

            results.append(NormalizedVulnerability(
                title=f"{cve_id} in {pkg_name}" if pkg_name else cve_id or "Sysdig Finding",
                description=description,
                remediation=f"Upgrade {pkg_name} to {fix_version}." if fix_version else "",
                affected_host=item.get("image") or "",
                cve_id=[cve_id] if cve_id.startswith("CVE-") else [],
                cvss_score=float(cvss_score) if cvss_score else None,
                risk_level=severity,
                source="sysdig",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return results
