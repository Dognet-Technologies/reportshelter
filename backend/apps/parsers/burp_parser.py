"""
Burp Suite XML parser — wraps the advanced parser from cyberreport_pro_parsers.
Handles XML v1.0/v1.1, request/response (plain and base64), all issue types.
Returns a list of OldNormalizedVulnerability compatible with deduplicate_and_save().
"""

from __future__ import annotations

import logging
from typing import IO

from .adapters import adapt_canonical_vuln
from .base import BaseParser, ParserError
from apps.vulnerabilities.deduplication import NormalizedVulnerability

logger = logging.getLogger(__name__)


class BurpParser(BaseParser):
    """
    Adapter wrapping the advanced BurpParser from cyberreport_pro_parsers.
    Supports Burp Suite Pro/Enterprise XML export.
    """

    tool_name = "burp"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.burp_parser import BurpParser as NewBurpParser

        data = file_obj.read()
        try:
            result = NewBurpParser().parse(data)
        except ValueError as exc:
            raise ParserError(str(exc)) from exc

        if result.parse_errors:
            logger.warning("[burp] Parse warnings: %s", "; ".join(result.parse_errors))

        return [adapt_canonical_vuln(v) for v in result.vulnerabilities]
