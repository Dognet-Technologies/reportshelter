"""
SonarQube JSON parser.

SonarQube exports take several forms. This parser handles the common
JSON export produced by the sonar-report tool (DefectDojo-style):
  {
    "projectName": "...",
    "rules": {rule_key: {name, htmlDesc}},
    "issues": [
      {
        "rule": "python:S4502",
        "message": "...",
        "severity": "BLOCKER|CRITICAL|MAJOR|MINOR|INFO",
        "component": "file path",
        "line": 42,
        "type": "VULNERABILITY|BUG|CODE_SMELL|SECURITY_HOTSPOT",
        "status": "OPEN|CONFIRMED|REOPENED|RESOLVED|CLOSED",
        "resolution": "FALSE-POSITIVE|WONTFIX|FIXED|REMOVED"
      }
    ]
  }

Also handles the native SonarQube API response format:
  {"issues": [...], "components": [...], "rules": [...]}
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "blocker": "critical",
    "critical": "high",
    "major": "medium",
    "minor": "low",
    "info": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower(), "info")


_TYPE_RELEVANT = {"vulnerability", "bug", "security_hotspot"}


class SonarQubeParser(BaseParser):
    """Parser for SonarQube JSON reports (sonar-report format and API exports)."""

    tool_name = "sonarqube"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid SonarQube JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("SonarQube JSON root must be an object.")

        project_name = data.get("projectName") or data.get("sonarComponent") or ""
        rules_dict: dict = data.get("rules") or {}

        # Normalize rules: can be dict {key: {name, htmlDesc}} or list [{key, name}]
        rules_lookup: dict[str, str] = {}
        if isinstance(rules_dict, dict):
            for k, v in rules_dict.items():
                rules_lookup[k] = v.get("name") or k if isinstance(v, dict) else k
        elif isinstance(rules_dict, list):
            for r in rules_dict:
                if isinstance(r, dict):
                    rules_lookup[r.get("key", "")] = r.get("name") or r.get("key", "")

        issues = data.get("issues") or []
        results: list[NormalizedVulnerability] = []

        for issue in issues:
            if not isinstance(issue, dict):
                continue

            issue_type = (issue.get("type") or "").lower()
            # Only report VULNERABILITY, BUG, and SECURITY_HOTSPOT
            if issue_type and issue_type not in _TYPE_RELEVANT:
                continue

            status = (issue.get("status") or "").upper()
            resolution = (issue.get("resolution") or "").upper()
            if status in ("CLOSED", "RESOLVED") or resolution in ("FALSE-POSITIVE", "WONTFIX", "FIXED", "REMOVED"):
                continue

            rule_key = issue.get("rule") or ""
            rule_name = rules_lookup.get(rule_key) or rule_key
            message = issue.get("message") or ""
            severity = _sev(issue.get("severity") or "")
            component = issue.get("component") or issue.get("textRange", {})
            if isinstance(component, str):
                # component is like "project:src/file.py"
                file_path = component.split(":")[-1] if ":" in component else component
            else:
                file_path = ""
            line = issue.get("line") or 0

            title = f"[{rule_key}] {message[:120]}" if message else rule_name

            description = (
                f"Project: {project_name}\n"
                f"Rule: {rule_name} ({rule_key})\n"
                f"File: {file_path}:{line}\n"
                f"Message: {message}"
            )

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                affected_host=file_path or project_name,
                risk_level=severity,
                category=rule_key,
                evidence_code=description[:4096],
                source="sonarqube",
                raw_output=json.dumps(issue, default=str)[:2048],
            ))

        return results
