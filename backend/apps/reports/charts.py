"""
Chart generation for reports.
All charts are generated as PNG images in memory (base64-encoded)
for embedding directly into Jinja2 HTML templates before WeasyPrint rendering.
"""

from __future__ import annotations

import base64
import io
from collections import Counter

import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

matplotlib.use("Agg")  # Non-interactive backend (no display required)


SEVERITY_COLORS = {
    "critical": "#dc2626",   # red-600
    "high": "#ea580c",       # orange-600
    "medium": "#d97706",     # amber-600
    "low": "#2563eb",        # blue-600
    "info": "#6b7280",       # gray-500
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _fig_to_base64(fig: plt.Figure) -> str:
    """Convert a matplotlib figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, transparent=False)
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return data


def severity_pie_chart(vulnerabilities: list) -> str:
    """
    Generate a pie chart showing vulnerability distribution by severity.
    Returns base64-encoded PNG.
    """
    counts = Counter(v.risk_level for v in vulnerabilities)
    labels = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    sizes = [counts[s] for s in labels]
    colors = [SEVERITY_COLORS[s] for s in labels]

    if not sizes:
        return ""

    fig, ax = plt.subplots(figsize=(6, 5))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct=lambda p: f"{p:.1f}%\n({int(round(p * sum(sizes) / 100))})",
        startangle=140,
        pctdistance=0.75,
    )
    for autotext in autotexts:
        autotext.set_fontsize(9)
    ax.set_title("Vulnerability Distribution by Severity", fontsize=13, pad=15)
    fig.tight_layout()
    return _fig_to_base64(fig)


def host_bar_chart(vulnerabilities: list) -> str:
    """
    Generate a horizontal bar chart of vulnerability counts per host.
    Returns base64-encoded PNG.
    """
    host_counts: dict[str, dict[str, int]] = {}
    for v in vulnerabilities:
        host = v.affected_host or "N/A"
        if host not in host_counts:
            host_counts[host] = {s: 0 for s in SEVERITY_ORDER}
        host_counts[host][v.risk_level] = host_counts[host].get(v.risk_level, 0) + 1

    if not host_counts:
        return ""

    # Sort by total desc, limit to top 20
    sorted_hosts = sorted(host_counts.items(), key=lambda kv: sum(kv[1].values()), reverse=True)[:20]
    hosts = [h for h, _ in sorted_hosts]
    fig, ax = plt.subplots(figsize=(8, max(4, len(hosts) * 0.4 + 1)))

    bottom = [0] * len(hosts)
    for severity in SEVERITY_ORDER:
        values = [host_counts[h].get(severity, 0) for h in hosts]
        bars = ax.barh(hosts, values, left=bottom, color=SEVERITY_COLORS[severity], label=severity.capitalize())
        bottom = [b + v for b, v in zip(bottom, values)]

    ax.set_xlabel("Number of Vulnerabilities")
    ax.set_title("Vulnerabilities per Host", fontsize=13)
    ax.legend(loc="lower right")
    ax.invert_yaxis()
    fig.tight_layout()
    return _fig_to_base64(fig)


def timeline_chart(timeline_data: list[dict]) -> str:
    """
    Generate a line chart showing vulnerability trends over time.
    timeline_data is the output of deduplication.build_timeline().
    Returns base64-encoded PNG.
    """
    if not timeline_data:
        return ""

    labels = [entry.get("subproject_title", "") for entry in timeline_data]
    x = list(range(len(labels)))

    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 1.2), 5))

    for severity in SEVERITY_ORDER:
        values = [entry["by_severity"].get(severity, 0) for entry in timeline_data]
        ax.plot(x, values, marker="o", label=severity.capitalize(), color=SEVERITY_COLORS[severity])

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("Count")
    ax.set_title("Vulnerability Trend Over Time", fontsize=13)
    ax.legend()
    ax.grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()
    return _fig_to_base64(fig)


def risk_matrix_chart(vulnerabilities: list) -> str:
    """
    Generate a risk matrix scatter plot (probability × impact).
    CVSS mapped to impact (X), EPSS mapped to probability (Y).
    Returns base64-encoded PNG.
    """
    scored = [v for v in vulnerabilities if v.cvss_score is not None]
    if not scored:
        return ""

    fig, ax = plt.subplots(figsize=(7, 6))

    for v in scored:
        x = v.cvss_score or 0
        y = (v.epss_score or 0) * 10  # scale EPSS to 0-10
        color = SEVERITY_COLORS.get(v.risk_level, "#6b7280")
        ax.scatter(x, y, color=color, alpha=0.7, s=80, zorder=3)

    # Quadrant lines
    ax.axvline(x=5.0, color="gray", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.axhline(y=5.0, color="gray", linestyle="--", linewidth=0.8, alpha=0.5)

    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.set_xlabel("CVSS Score (Impact)")
    ax.set_ylabel("EPSS × 10 (Probability)")
    ax.set_title("Risk Matrix", fontsize=13)

    # Legend
    legend_patches = [
        mpatches.Patch(color=SEVERITY_COLORS[s], label=s.capitalize())
        for s in SEVERITY_ORDER
    ]
    ax.legend(handles=legend_patches, loc="upper left")
    ax.grid(True, linestyle="--", alpha=0.3)
    fig.tight_layout()
    return _fig_to_base64(fig)
