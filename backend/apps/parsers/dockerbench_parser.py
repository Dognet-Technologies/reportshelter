"""
Docker Bench Security JSON parser.

docker-bench-security produces:
  dockerbenchsecurity — version
  tests[]             — test sections
    id      — section ID (e.g. "1")
    desc    — section description
    results[] — individual check results
      id          — check ID (e.g. "1.1.1")
      desc        — check description
      result      — PASS | WARN | INFO | NOTE
      remediation — how to fix (on WARN/FAIL)
      details     — optional extra detail
      items[]     — optional list of affected items

Only WARN and INFO results are reported as findings.
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


def _sev(result: str) -> str:
    r = (result or "").upper()
    if r == "WARN":
        return "medium"
    if r == "INFO":
        return "low"
    return "info"


class DockerBenchParser(BaseParser):
    """Parser for Docker Bench Security JSON reports."""

    tool_name = "dockerbench"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Docker Bench JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("Docker Bench JSON root must be an object.")

        tests = data.get("tests") or []
        results: list[NormalizedVulnerability] = []

        for section in tests:
            if not isinstance(section, dict):
                continue

            section_desc = section.get("desc") or ""
            check_results = section.get("results") or []

            for check in check_results:
                if not isinstance(check, dict):
                    continue

                result_str = (check.get("result") or "").upper()
                if result_str not in ("WARN", "INFO", "NOTE"):
                    continue

                check_id = check.get("id") or ""
                desc = check.get("desc") or ""
                remediation = check.get("remediation") or ""
                details = check.get("details") or ""
                items = check.get("items") or []

                title = f"Docker Bench [{check_id}]: {desc}"

                description = f"Section: {section_desc}\nCheck: {check_id} — {desc}"
                if details:
                    description += f"\nDetails: {details}"
                if items:
                    description += f"\nAffected: {', '.join(str(i) for i in items[:10])}"

                results.append(NormalizedVulnerability(
                    title=title,
                    description=description,
                    remediation=remediation,
                    affected_host="docker",
                    risk_level=_sev(result_str),
                    category="CIS Docker Benchmark",
                    evidence_code=description[:4096],
                    source="dockerbench",
                    raw_output=json.dumps(check, default=str)[:2048],
                ))

        return results
