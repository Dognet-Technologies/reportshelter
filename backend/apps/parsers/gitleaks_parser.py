"""
Gitleaks JSON parser.

Gitleaks writes a JSON array where each element represents a secret match:
  rule        — rule name (e.g. "Asymmetric Private Key")
  file        — file path where the secret was found
  line / lineNumber — line number (field name varies by version)
  offender    — the matched text (potentially sensitive)
  commit      — git commit SHA
  author      — committer name
  email       — committer email
  date        — commit date
  tags        — comma-separated tags
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


class GitleaksParser(BaseParser):
    """Parser for Gitleaks JSON output."""

    tool_name = "gitleaks"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Gitleaks JSON: {exc}") from exc

        if data is None:
            # gitleaks --no-git outputs null when no secrets found
            return []
        if not isinstance(data, list):
            raise ParserError("Gitleaks JSON must be a top-level array.")

        results: list[NormalizedVulnerability] = []
        for item in data:
            if not isinstance(item, dict):
                continue

            rule = item.get("rule") or item.get("Description") or "Secret Exposure"
            file_path = item.get("file") or item.get("File") or ""
            commit = item.get("commit") or item.get("Commit") or ""
            author = item.get("author") or item.get("Author") or ""
            date = item.get("date") or item.get("Date") or ""
            tags = item.get("tags") or item.get("Tags") or ""
            # offender may contain actual secret — truncate for safety
            offender = (item.get("offender") or item.get("Secret") or "")[:120]

            title = f"Secret Exposure: {rule}"
            if file_path:
                title += f" in {file_path.split('/')[-1]}"

            description = (
                f"Gitleaks detected a potential secret matching rule '{rule}'.\n"
                f"File: {file_path}\n"
                f"Commit: {commit}\n"
                f"Author: {author} ({date})"
            )
            if tags:
                description += f"\nTags: {tags}"

            evidence = description
            if offender:
                evidence += f"\nMatch (truncated): {offender}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                affected_host=file_path,
                risk_level="high",
                category="CWE-798",  # Use of Hard-coded Credentials
                evidence_code=evidence[:4096],
                source="gitleaks",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return results
