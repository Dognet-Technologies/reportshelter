"""
CodeChecker JSON parser.

CodeChecker exports:
  version   — schema version (1)
  reports[] — list of findings
    file.path         — source file path
    line / column     — location
    message           — checker message
    checker_name      — e.g. "clang-diagnostic-sign-compare"
    severity          — CRITICAL | HIGH | MEDIUM | LOW | INFO | STYLE | UNSPECIFIED
    analyzer_name     — e.g. "clang-tidy"
    category          — checker category
    report_hash       — dedup hash
    review_status     — unreviewed | false_positive | confirmed | suppress
"""

from __future__ import annotations

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
    "info": "info",
    "style": "info",
    "unspecified": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower(), "info")


class CodeCheckerParser(BaseParser):
    """Parser for CodeChecker JSON reports."""

    tool_name = "codechecker"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid CodeChecker JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("CodeChecker JSON root must be an object.")

        reports = data.get("reports") or []
        results: list[NormalizedVulnerability] = []

        for report in reports:
            if not isinstance(report, dict):
                continue

            review_status = (report.get("review_status") or "").lower()
            if review_status in ("false_positive", "suppress"):
                continue

            file_info = report.get("file") or {}
            file_path = file_info.get("path") or file_info.get("original_path") or ""
            line = report.get("line") or 0
            column = report.get("column") or 0
            message = report.get("message") or ""
            checker = report.get("checker_name") or ""
            severity = _sev(report.get("severity") or "")
            analyzer = report.get("analyzer_name") or ""
            category = report.get("category") or ""

            title = f"[{checker}] {message[:80]}" if checker else message[:80] or "CodeChecker Finding"
            description = (
                f"Analyzer: {analyzer}\n"
                f"Checker: {checker}\n"
                f"File: {file_path}:{line}:{column}\n"
                f"Message: {message}"
            )

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                affected_host=file_path.split("/")[-1] if file_path else "",
                risk_level=severity,
                category=category or checker,
                evidence_code=description[:4096],
                source="codechecker",
                raw_output=json.dumps(report, default=str)[:2048],
            ))

        return results
