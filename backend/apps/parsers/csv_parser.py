"""
Generic CSV parser.
Supports configurable column mapping for any CSV-based scanner output.
"""

from __future__ import annotations

import csv
import io
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError


# Default column mapping: CSV header → NormalizedVulnerability field
DEFAULT_COLUMN_MAP: dict[str, str] = {
    "title": "title",
    "name": "title",
    "vulnerability": "title",
    "finding": "title",
    "description": "description",
    "detail": "description",
    "summary": "description",
    "remediation": "remediation",
    "solution": "remediation",
    "fix": "remediation",
    "host": "affected_host",
    "ip": "affected_host",
    "address": "affected_host",
    "port": "affected_port",
    "service": "affected_service",
    "cve": "cve_id",
    "cve_id": "cve_id",
    "cvss": "cvss_score",
    "cvss_score": "cvss_score",
    "epss": "epss_score",
    "severity": "risk_level",
    "risk": "risk_level",
    "risk_level": "risk_level",
    "evidence": "evidence_code",
    "proof": "evidence_code",
    "output": "evidence_code",
}

RISK_NORMALIZATION: dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "h": "high",
    "medium": "medium",
    "med": "medium",
    "m": "medium",
    "moderate": "medium",
    "low": "low",
    "l": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "i": "info",
    "none": "info",
}


class CSVParser(BaseParser):
    """
    Generic CSV parser with auto-detection of column headers.
    Custom column_map can be provided to override the default mapping.
    """

    tool_name = "csv"

    def __init__(self, column_map: dict[str, str] | None = None) -> None:
        self.column_map = {k.lower(): v for k, v in (column_map or DEFAULT_COLUMN_MAP).items()}

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            text = file_obj.read().decode("utf-8-sig")  # handle BOM
        except UnicodeDecodeError:
            try:
                file_obj.seek(0)
                text = file_obj.read().decode("latin-1")
            except UnicodeDecodeError as exc:
                raise ParserError(f"Cannot decode CSV file: {exc}") from exc

        reader = csv.DictReader(io.StringIO(text))

        if reader.fieldnames is None:
            raise ParserError("CSV file has no headers.")

        # Build mapping: csv_header → vuln field
        field_map: dict[str, str] = {}
        for header in reader.fieldnames:
            normalized = header.strip().lower().replace(" ", "_")
            if normalized in self.column_map:
                field_map[header] = self.column_map[normalized]

        results: list[NormalizedVulnerability] = []

        for i, row in enumerate(reader):
            mapped: dict[str, str] = {}
            for csv_col, vuln_field in field_map.items():
                value = row.get(csv_col, "").strip()
                if value:
                    mapped[vuln_field] = value

            title = mapped.get("title", "").strip()
            if not title:
                # Skip rows without a title
                continue

            # Normalize risk level
            risk_raw = mapped.get("risk_level", "medium").lower()
            risk_level = RISK_NORMALIZATION.get(risk_raw, "medium")

            # Parse numeric CVSS
            cvss_score = None
            cvss_raw = mapped.get("cvss_score", "")
            if cvss_raw:
                try:
                    cvss_score = float(cvss_raw)
                    if not (0.0 <= cvss_score <= 10.0):
                        cvss_score = None
                except ValueError:
                    pass

            # Parse numeric EPSS
            epss_score = None
            epss_raw = mapped.get("epss_score", "")
            if epss_raw:
                try:
                    epss_score = float(epss_raw)
                    if not (0.0 <= epss_score <= 1.0):
                        epss_score = None
                except ValueError:
                    pass

            results.append(NormalizedVulnerability(
                title=title,
                description=mapped.get("description", ""),
                remediation=mapped.get("remediation", ""),
                affected_host=mapped.get("affected_host", ""),
                affected_port=mapped.get("affected_port", ""),
                affected_service=mapped.get("affected_service", ""),
                cve_id=mapped.get("cve_id", ""),
                cvss_score=cvss_score,
                epss_score=epss_score,
                risk_level=risk_level,
                evidence_code=mapped.get("evidence_code", ""),
                source=self.tool_name,
                raw_output=str(dict(row))[:2048],
            ))

        return results
