"""
Base parser interface for scanner output files.
All parsers must implement the BaseParser interface.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """
    Abstract base class for all scanner parsers.
    Subclasses implement `parse()` to return a list of NormalizedVulnerability.
    """

    tool_name: str = "unknown"

    @abstractmethod
    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        """
        Parse the given file object and return normalized vulnerabilities.

        Args:
            file_obj: An open binary file-like object.

        Returns:
            List of NormalizedVulnerability instances.

        Raises:
            ParserError: On malformed or unsupported input.
        """

    def safe_parse(self, file_obj: IO[bytes]) -> tuple[list[NormalizedVulnerability], str | None]:
        """
        Wraps parse() with error handling.
        Returns (results, error_message). error_message is None on success.
        """
        try:
            results = self.parse(file_obj)
            logger.info("[%s] Parsed %d vulnerabilities.", self.tool_name, len(results))
            return results, None
        except ParserError as exc:
            logger.error("[%s] Parse error: %s", self.tool_name, exc)
            return [], str(exc)
        except Exception as exc:
            logger.exception("[%s] Unexpected error during parsing.", self.tool_name)
            return [], f"Unexpected error: {exc}"


class ParserError(Exception):
    """Raised when a parser cannot process the given file."""
