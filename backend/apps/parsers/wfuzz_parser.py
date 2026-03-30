"""
Wfuzz JSON parser.

Wfuzz -f results.json,json writes a JSON array where each element is a
response that passed the filter (i.e. was not hidden). Fields:
  url      — full URL fuzzed
  code     — HTTP response code
  chars    — response character count
  lines    — response line count
  words    — response word count
  payload  — payload string used
  method   — HTTP method

Wfuzz findings are not traditional vulnerabilities — each matching
response is a potential exposed endpoint or directory/file disclosure.
Severity is set based on HTTP status code.
"""

from __future__ import annotations

import json
import logging
from typing import IO
from urllib.parse import urlparse

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


def _severity_from_code(code: int) -> str:
    if code in (200, 201, 204):
        return "medium"
    if code in (301, 302, 307, 308):
        return "low"
    if code in (401, 403):
        return "low"
    if code in (500, 502, 503):
        return "medium"
    return "info"


class WfuzzParser(BaseParser):
    """Parser for Wfuzz JSON output."""

    tool_name = "wfuzz"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Wfuzz JSON: {exc}") from exc

        if not isinstance(data, list):
            raise ParserError("Wfuzz JSON must be a top-level array.")

        results: list[NormalizedVulnerability] = []
        for item in data:
            if not isinstance(item, dict):
                continue

            url = item.get("url") or ""
            code = int(item.get("code") or 0)
            chars = item.get("chars") or 0
            lines = item.get("lines") or 0
            words = item.get("words") or 0
            payload = item.get("payload") or ""
            method = item.get("method") or "GET"

            if not url:
                continue

            parsed = urlparse(url)
            host = parsed.hostname or url
            port: int | None = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80

            path = parsed.path or "/"
            title = f"Exposed Resource: {method} {path} [{code}]"

            description = (
                f"Wfuzz discovered an accessible resource.\n"
                f"URL: {url}\n"
                f"Method: {method}\n"
                f"HTTP Status: {code}\n"
                f"Response: {chars} chars, {lines} lines, {words} words"
            )
            if payload:
                description += f"\nPayload: {payload[:200]}"

            results.append(NormalizedVulnerability(
                title=title,
                description=description,
                affected_host=host,
                affected_port=port,
                affected_service="http" if parsed.scheme == "http" else "https",
                risk_level=_severity_from_code(code),
                evidence_code=description[:4096],
                source="wfuzz",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return results
