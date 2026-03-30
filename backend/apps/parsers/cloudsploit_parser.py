"""
CloudSploit JSON parser.

CloudSploit exports a JSON array of findings:
  plugin      — check plugin name (e.g. "stackTerminationProtection")
  category    — AWS service category (e.g. "CloudFormation")
  title       — human-readable title
  description — what was checked
  resource    — AWS resource ARN
  region      — AWS region
  status      — PASS | FAIL | WARN | UNKNOWN
  message     — result detail
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


def _sev(status: str) -> str:
    mapping = {
        "fail": "high",
        "warn": "medium",
        "unknown": "info",
        "pass": "info",
    }
    return mapping.get((status or "").lower(), "info")


class CloudSploitParser(BaseParser):
    """Parser for CloudSploit JSON reports."""

    tool_name = "cloudsploit"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid CloudSploit JSON: {exc}") from exc

        if not isinstance(data, list):
            raise ParserError("CloudSploit JSON must be a top-level array.")

        results: list[NormalizedVulnerability] = []

        for item in data:
            if not isinstance(item, dict):
                continue

            status = item.get("status") or ""
            if (status or "").upper() == "PASS":
                continue

            plugin = item.get("plugin") or ""
            category = item.get("category") or ""
            title = item.get("title") or plugin or "Cloud Misconfiguration"
            description = item.get("description") or ""
            resource = item.get("resource") or ""
            region = item.get("region") or ""
            message = item.get("message") or ""

            if message and description:
                description = f"{description}\n\nResult: {message}"
            elif message:
                description = message

            evidence = f"Plugin: {plugin}\nCategory: {category}\nStatus: {status}"
            if region:
                evidence += f"\nRegion: {region}"
            if resource:
                evidence += f"\nResource: {resource}"

            affected_host = resource[-120:] if len(resource) > 120 else resource

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                affected_host=affected_host,
                risk_level=_sev(status),
                category=category,
                evidence_code=evidence[:4096],
                source="cloudsploit",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return results
