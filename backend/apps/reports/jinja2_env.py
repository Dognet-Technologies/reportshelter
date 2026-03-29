"""Jinja2 environment factory for report templates."""

import re
from datetime import date, datetime

from jinja2 import Environment


def _format_date(value: date | datetime | None, fmt: str = "%d %B %Y") -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime(fmt)
    return value.strftime(fmt)


def _severity_badge(level: str) -> str:
    """Return an HTML badge for a severity level."""
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }
    color = colors.get(level.lower(), "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:10px;font-weight:bold;">'
        f"{level.upper()}</span>"
    )


def _cvss_color(score: float | None) -> str:
    if score is None:
        return "#6b7280"
    if score >= 9.0:
        return "#dc2626"
    if score >= 7.0:
        return "#ea580c"
    if score >= 4.0:
        return "#d97706"
    return "#2563eb"


def _test_search(value: object, pattern: str) -> bool:
    """
    Jinja2 test: selectattr("field", "search", "pattern").
    Returns True if the regex pattern matches anywhere in the string value.
    """
    return bool(re.search(pattern, str(value) if value is not None else ""))


def environment(**options) -> Environment:
    """Create the Jinja2 environment with custom filters and globals."""
    env = Environment(**options)
    env.filters["format_date"] = _format_date
    env.filters["severity_badge"] = _severity_badge
    env.filters["cvss_color"] = _cvss_color
    env.globals["now"] = datetime.utcnow
    # Custom tests
    env.tests["search"] = _test_search
    return env
