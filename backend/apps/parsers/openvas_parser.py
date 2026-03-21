"""
OpenVAS / Greenbone and Nessus parsers — native implementation, no external deps.

Supports:
  - OpenVAS / Greenbone CSV (auto-detected by headers)
  - OpenVAS / Greenbone XML (GMP report format)
  - Nessus CSV

Tool names registered in the parser registry:
  "openvas"  → OpenVasParser  (auto-detects XML vs CSV)
  "nessus"   → NessusParser   (Nessus .csv)
"""

from __future__ import annotations

import csv
import io
import logging
import xml.etree.ElementTree as ET
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


# ── Severity helpers ─────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "log": "info",
    "none": "info",
    "info": "info",
    "informational": "info",
    "": "info",
}


def _normalize_severity(raw: str) -> str:
    """Map free-text severity to a canonical risk_level string."""
    return _SEVERITY_MAP.get(raw.strip().lower(), "medium")


def _cvss_to_severity(score: float | None) -> str:
    """Convert a CVSS numeric score to a risk_level string."""
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _parse_cvss(raw: str) -> float | None:
    """Parse a CVSS score string; return None if invalid."""
    try:
        v = float(raw.strip())
        return v if 0.0 <= v <= 10.0 else None
    except (ValueError, AttributeError):
        return None


# ── OpenVAS CSV ───────────────────────────────────────────────────────────────

# Typical OpenVAS / Greenbone CSV column headers (case-insensitive).
# Different versions of Greenbone use slightly different names.
_OV_COLUMN_ALIASES: dict[str, str] = {
    # Target
    "ip": "ip",
    "hostname": "hostname",
    "port": "port",
    "port protocol": "port_proto",
    # Scoring
    "cvss": "cvss",
    "severity": "severity",
    "qod": "qod",
    # Finding
    "nvt name": "title",
    "solution type": "solution_type",
    "summary": "summary",
    "specific result": "specific_result",
    "nvt oid": "nvt_oid",
    "cves": "cves",
    "impact": "impact",
    "solution": "solution",
    "affected software/os": "affected_sw",
    "vulnerability insight": "vuln_insight",
    "vulnerability detection method": "detect_method",
    "product detection result": "product_detection",
    "bids": "bids",
    "certs": "certs",
    "other references": "other_refs",
    # Task meta
    "task id": "task_id",
    "task name": "task_name",
    "timestamp": "timestamp",
    "result id": "result_id",
}


def _map_openvas_headers(fieldnames: list[str]) -> dict[str, str]:
    """Return a mapping {csv_header → internal_key} for OpenVAS column names."""
    mapping: dict[str, str] = {}
    for h in fieldnames:
        key = h.strip().lower()
        if key in _OV_COLUMN_ALIASES:
            mapping[h] = _OV_COLUMN_ALIASES[key]
    return mapping


def _is_openvas_csv(fieldnames: list[str]) -> bool:
    """Heuristic: at least 3 known OpenVAS column aliases must be present."""
    lower = {h.strip().lower() for h in fieldnames}
    known = set(_OV_COLUMN_ALIASES.keys())
    return len(lower & known) >= 3


def _parse_openvas_csv(data: bytes) -> list[NormalizedVulnerability]:
    """Parse an OpenVAS / Greenbone CSV export."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="replace")

    reader = csv.DictReader(io.StringIO(text))
    fieldnames = list(reader.fieldnames or [])

    if not fieldnames:
        raise ParserError("OpenVAS CSV: empty or missing header row.")

    if not _is_openvas_csv(fieldnames):
        raise ParserError(
            "OpenVAS CSV: unrecognised column headers. "
            f"Got: {fieldnames[:10]}. "
            "Expected OpenVAS/Greenbone CSV format."
        )

    col = _map_openvas_headers(fieldnames)
    results: list[NormalizedVulnerability] = []

    for row in reader:
        def g(key: str) -> str:
            """Get value by internal key, strip whitespace."""
            for h, k in col.items():
                if k == key:
                    return row.get(h, "").strip()
            return ""

        title = g("title")
        if not title:
            continue  # skip empty / log rows without a name

        cvss_score = _parse_cvss(g("cvss"))
        severity_raw = g("severity")
        if severity_raw:
            risk_level = _normalize_severity(severity_raw)
        else:
            risk_level = _cvss_to_severity(cvss_score)

        # Skip pure log/debug entries (severity = 0 and no meaningful title)
        if cvss_score == 0.0 and risk_level == "info" and len(title) < 10:
            continue

        # Build description from available narrative fields
        parts = []
        for key, label in [
            ("summary", "Summary"),
            ("vuln_insight", "Insight"),
            ("impact", "Impact"),
            ("detect_method", "Detection"),
        ]:
            val = g(key)
            if val:
                parts.append(f"{label}: {val}")
        description = "\n\n".join(parts)

        evidence = g("specific_result")

        remediation_parts = []
        for key, label in [("solution", "Solution"), ("affected_sw", "Affected Software")]:
            val = g(key)
            if val:
                remediation_parts.append(f"{label}: {val}")
        remediation = "\n\n".join(remediation_parts)

        # CVEs: may be a semicolon/comma separated list
        cves_raw = g("cves")
        cve_id = ", ".join(
            c.strip()
            for c in cves_raw.replace(";", ",").split(",")
            if c.strip().upper().startswith("CVE-")
        )

        host = g("hostname") or g("ip")
        port_raw = g("port")
        port_proto = g("port_proto")
        port = port_raw if port_raw not in ("0", "general", "") else ""
        service = port_proto if port_proto else ""

        raw_out = f"NVT OID: {g('nvt_oid')} | Task: {g('task_name')} | Timestamp: {g('timestamp')}"

        results.append(
            NormalizedVulnerability(
                title=title,
                description=description,
                remediation=remediation,
                affected_host=host,
                affected_port=port,
                affected_service=service,
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector="",
                risk_level=risk_level,
                evidence_code=evidence[:4096] if evidence else "",
                source="openvas",
                raw_output=raw_out[:2048],
            )
        )

    return results


# ── OpenVAS XML ───────────────────────────────────────────────────────────────


def _parse_openvas_xml(data: bytes) -> list[NormalizedVulnerability]:
    """Parse an OpenVAS / Greenbone XML report (GMP format)."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ParserError(f"OpenVAS XML: invalid XML — {exc}") from exc

    # The root may be <report> or <get_reports_response>
    # Locate all <result> elements
    results_el = root.findall(".//result")
    if not results_el:
        raise ParserError("OpenVAS XML: no <result> elements found.")

    vulns: list[NormalizedVulnerability] = []

    for r in results_el:
        def txt(tag: str) -> str:
            el = r.find(tag)
            return (el.text or "").strip() if el is not None else ""

        title = txt("name")
        if not title:
            continue

        severity_str = txt("severity")
        cvss_score = _parse_cvss(severity_str)
        risk_level = _cvss_to_severity(cvss_score)

        description = txt("description")

        # NVT metadata
        nvt = r.find("nvt")
        nvt_name = ""
        cve_id = ""
        solution = ""
        if nvt is not None:
            nvt_name = (nvt.get("oid") or "") if not title else title
            # CVEs under <refs><ref type="cve">
            cves = [
                ref.get("id", "")
                for ref in nvt.findall(".//ref[@type='cve']")
                if ref.get("id", "").startswith("CVE-")
            ]
            cve_id = ", ".join(cves)
            sol_el = nvt.find("solution")
            solution = (sol_el.text or "").strip() if sol_el is not None else ""

        # Host
        host_el = r.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        hostname_el = r.find("host/hostname")
        if hostname_el is not None and hostname_el.text:
            host = hostname_el.text.strip() or host

        # Port
        port_raw = txt("port")
        port = ""
        service = ""
        if port_raw and "/" in port_raw:
            port_num, proto = port_raw.split("/", 1)
            port = port_num.strip() if port_num.strip() not in ("0", "general") else ""
            service = proto.strip()
        elif port_raw not in ("0", "general", ""):
            port = port_raw

        evidence = txt("description") or ""

        vulns.append(
            NormalizedVulnerability(
                title=title,
                description=description,
                remediation=solution,
                affected_host=host,
                affected_port=port,
                affected_service=service,
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_vector="",
                risk_level=risk_level,
                evidence_code=evidence[:4096],
                source="openvas",
                raw_output=f"NVT OID: {nvt.get('oid', '') if nvt is not None else ''}",
            )
        )

    return vulns


# ── Main parser class ─────────────────────────────────────────────────────────


class OpenVasParser(BaseParser):
    """
    Native OpenVAS / Greenbone parser.
    Auto-detects CSV vs XML format from file content.
    No external library dependencies.
    """

    tool_name = "openvas"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        data = file_obj.read()
        if not data:
            raise ParserError("OpenVAS: uploaded file is empty.")

        # Detect format: XML starts with '<', CSV starts with plain text/BOM
        stripped = data.lstrip()
        if stripped.startswith(b"<"):
            logger.info("[openvas] Detected XML format.")
            return _parse_openvas_xml(data)
        else:
            logger.info("[openvas] Detected CSV format.")
            return _parse_openvas_csv(data)


# ── Nessus CSV ────────────────────────────────────────────────────────────────

# Nessus CSV standard columns
_NESSUS_COLUMNS: dict[str, str] = {
    "plugin name": "title",
    "name": "title",
    "description": "description",
    "synopsis": "description",
    "solution": "remediation",
    "host": "host",
    "ip address": "host",
    "port": "port",
    "protocol": "service",
    "cve": "cve_id",
    "cvss v2.0 base score": "cvss",
    "cvss v3.0 base score": "cvss3",
    "risk": "severity",
    "severity": "severity",
    "plugin output": "evidence",
    "see also": "refs",
}


class NessusParser(BaseParser):
    """
    Native Nessus CSV export parser.
    No external library dependencies.
    """

    tool_name = "nessus"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        data = file_obj.read()
        if not data:
            raise ParserError("Nessus: uploaded file is empty.")

        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")

        reader = csv.DictReader(io.StringIO(text))
        fieldnames = list(reader.fieldnames or [])

        if not fieldnames:
            raise ParserError("Nessus CSV: empty or missing header row.")

        # Build column map
        col_map: dict[str, str] = {}
        for h in fieldnames:
            key = h.strip().lower()
            if key in _NESSUS_COLUMNS:
                col_map[h] = _NESSUS_COLUMNS[key]

        results: list[NormalizedVulnerability] = []

        for row in reader:
            def g(internal: str) -> str:
                for hdr, mapped in col_map.items():
                    if mapped == internal:
                        return row.get(hdr, "").strip()
                return ""

            title = g("title")
            if not title:
                continue

            # Skip informational / None-risk rows
            severity_raw = g("severity")
            if severity_raw.lower() in ("none", "0"):
                continue

            risk_level = _normalize_severity(severity_raw)

            # Prefer CVSSv3 over v2
            cvss_score = _parse_cvss(g("cvss3")) or _parse_cvss(g("cvss"))

            # CVE: may be space-separated list
            cve_raw = g("cve_id")
            cve_id = ", ".join(
                c.strip()
                for c in cve_raw.replace(";", " ").split()
                if c.strip().upper().startswith("CVE-")
            )

            description = g("description")
            evidence = g("evidence")

            results.append(
                NormalizedVulnerability(
                    title=title,
                    description=description,
                    remediation=g("remediation"),
                    affected_host=g("host"),
                    affected_port=g("port"),
                    affected_service=g("service"),
                    cve_id=cve_id,
                    cvss_score=cvss_score,
                    cvss_vector="",
                    risk_level=risk_level,
                    evidence_code=evidence[:4096] if evidence else "",
                    source="nessus",
                    raw_output=str({k: row.get(k, "") for k in list(row.keys())[:8]})[:2048],
                )
            )

        return results
