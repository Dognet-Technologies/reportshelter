"""
Chart generation for reports.
All charts are generated as PNG images in memory (base64-encoded)
for embedding directly into Jinja2 HTML templates before WeasyPrint rendering.

Audience levels affect rendering detail:
  executive   — high-level, minimal numbers, visual emphasis
  management  — count + percentage, moderate detail
  technical   — full data, tables, detailed breakdown
"""

from __future__ import annotations

import base64
import io
import re
from collections import Counter, defaultdict

import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

matplotlib.use("Agg")  # Non-interactive backend (no display required)

AudienceLevel = str  # "executive" | "management" | "technical"

SEVERITY_COLORS = {
    "critical": "#dc2626",   # red-600
    "high": "#ea580c",       # orange-600
    "medium": "#d97706",     # amber-600
    "low": "#2563eb",        # blue-600
    "info": "#6b7280",       # gray-500
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

EFFORT_COLORS = {
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#22c55e",
}


def _fig_to_base64(fig: plt.Figure) -> str:
    """Convert a matplotlib figure to a base64-encoded PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=150, transparent=False)
    buf.seek(0)
    data = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return data


# ---------------------------------------------------------------------------
# 1. severity_donut  (was: severity_pie_chart)
# ---------------------------------------------------------------------------

def severity_pie_chart(
    vulnerabilities: list,
    variant: str = "Donut",
    audience: AudienceLevel = "technical",
) -> str:
    """
    Pie / donut chart — vulnerability distribution by severity.

    Audience behaviour:
      executive   — percentages only, no counts in wedge labels
      management  — percentage + count
      technical   — percentage + count (default)

    Returns base64-encoded PNG.
    """
    counts = Counter(v.risk_level for v in vulnerabilities)
    labels = [s for s in SEVERITY_ORDER if counts.get(s, 0) > 0]
    sizes = [counts[s] for s in labels]
    colors = [SEVERITY_COLORS[s] for s in labels]
    total = sum(sizes)

    if not sizes:
        return ""

    fig, ax = plt.subplots(figsize=(6, 5))

    if audience == "executive":
        autopct_fn = lambda p: f"{p:.1f}%"
    else:
        autopct_fn = lambda p: f"{p:.1f}%\n({int(round(p * total / 100))})"

    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct=autopct_fn,
        startangle=140,
        pctdistance=0.75,
    )
    for autotext in autotexts:
        autotext.set_fontsize(9)

    if variant.lower() != "pie":
        centre_circle = plt.Circle((0, 0), 0.55, fc="white")
        ax.add_artist(centre_circle)

    ax.set_title("Vulnerability Distribution by Severity", fontsize=13, pad=15)
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 2. risk_gauge
# ---------------------------------------------------------------------------

def _weighted_risk_score(vulnerabilities: list) -> float:
    """
    Compute a 0-100 project risk score using the WEIGHTED method from the spec:

        score = (critical*10 + high*7 + medium*4 + low*1) / total_findings
        score_normalized = min(score * 10, 100)

    Falls back to CVSS_AVG if no findings have a known risk_level.
    """
    from collections import Counter
    counts = Counter(v.risk_level for v in vulnerabilities)
    total = sum(counts.values())
    if total == 0:
        return 0.0
    raw = (
        counts.get("critical", 0) * 10.0
        + counts.get("high", 0) * 7.0
        + counts.get("medium", 0) * 4.0
        + counts.get("low", 0) * 1.0
    ) / total
    return min(raw * 10, 100.0)


def _gauge_label(score: float) -> tuple[str, str]:
    """Return (risk label, color) for a 0-100 score per spec color thresholds."""
    if score <= 25:
        return "LOW", "#27AE60"
    if score <= 50:
        return "MEDIUM", "#F39C12"
    if score <= 75:
        return "HIGH", "#E67E22"
    return "CRITICAL", "#C0392B"


def risk_gauge_chart(vulnerabilities: list, audience: AudienceLevel = "executive") -> str:
    """
    Semicircular gauge chart showing overall project risk score (0-100).

    Score is computed using the WEIGHTED method (spec §6):
        (critical*10 + high*7 + medium*4 + low*1) / total_findings * 10, capped at 100.

    Color zones per spec:
        0-25 GREEN (#27AE60) LOW
        26-50 YELLOW (#F39C12) MEDIUM
        51-75 ORANGE (#E67E22) HIGH
        76-100 RED (#C0392B) CRITICAL

    Audience behaviour:
      executive   — gauge only, large label + risk level text
      management  — gauge + numeric score + breakdown hint
      technical   — gauge + score + formula note

    Returns base64-encoded PNG.
    """
    if not vulnerabilities:
        return ""

    score = _weighted_risk_score(vulnerabilities)
    risk_label, label_color = _gauge_label(score)

    fig, ax = plt.subplots(figsize=(6, 4), subplot_kw={"aspect": "equal"})
    ax.set_xlim(-1.3, 1.3)
    ax.set_ylim(-0.3, 1.3)
    ax.axis("off")

    # 4 color zones matching spec thresholds: 0-25, 26-50, 51-75, 76-100
    zone_colors = ["#27AE60", "#F39C12", "#E67E22", "#C0392B"]
    zone_fracs  = [0.25, 0.25, 0.25, 0.25]  # equal 25% bands
    theta_start = np.pi
    for color, frac in zip(zone_colors, zone_fracs):
        theta_end = theta_start - frac * np.pi
        t = np.linspace(theta_start, theta_end, 50)
        x_outer = np.cos(t) * 1.0
        y_outer = np.sin(t) * 1.0
        x_inner = np.cos(t) * 0.7
        y_inner = np.sin(t) * 0.7
        xs = np.concatenate([x_outer, x_inner[::-1]])
        ys = np.concatenate([y_outer, y_inner[::-1]])
        ax.fill(xs, ys, color=color, alpha=0.85)
        theta_start = theta_end

    # Needle: map score 0-100 → angle π→0
    needle_angle = np.pi - (score / 100.0) * np.pi
    needle_x = np.cos(needle_angle) * 0.82
    needle_y = np.sin(needle_angle) * 0.82
    ax.annotate(
        "",
        xy=(needle_x, needle_y),
        xytext=(0, 0),
        arrowprops={"arrowstyle": "->", "color": "#1e293b", "lw": 2.5},
    )
    ax.add_patch(plt.Circle((0, 0), 0.06, color="#1e293b", zorder=5))

    # Score and label text
    ax.text(0, -0.10, f"{score:.0f}", ha="center", va="center",
            fontsize=22, fontweight="bold", color="#1e293b")
    ax.text(0, -0.28, risk_label, ha="center", va="center",
            fontsize=13, fontweight="bold", color=label_color)

    if audience != "executive":
        from collections import Counter
        counts = Counter(v.risk_level for v in vulnerabilities)
        note_parts = []
        for level in ("critical", "high", "medium", "low"):
            if counts.get(level, 0):
                note_parts.append(f"{counts[level]} {level}")
        if note_parts:
            ax.text(0, -0.48, "  ·  ".join(note_parts), ha="center", va="center",
                    fontsize=7, color="#6b7280")

    ax.set_title("Overall Project Risk Score (0–100)", fontsize=12, pad=8)
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 3. historical_trend  (was: timeline_chart)
# ---------------------------------------------------------------------------

def timeline_chart(
    timeline_data: list[dict],
    audience: AudienceLevel = "technical",
) -> str:
    """
    Line chart showing vulnerability trends over SubProject scans.
    timeline_data is the output of deduplication.build_timeline().

    Audience behaviour:
      executive   — total line only
      management  — critical+high stacked
      technical   — all severities

    Returns base64-encoded PNG.
    """
    if not timeline_data:
        return ""

    labels = [entry.get("subproject_title", "") for entry in timeline_data]
    x = list(range(len(labels)))

    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 1.2), 5))

    if audience == "executive":
        totals = [entry.get("total", 0) for entry in timeline_data]
        ax.plot(x, totals, marker="o", label="Total", color="#6366f1", linewidth=2)
    elif audience == "management":
        for sev in ["critical", "high"]:
            values = [entry["by_severity"].get(sev, 0) for entry in timeline_data]
            ax.plot(x, values, marker="o", label=sev.capitalize(),
                    color=SEVERITY_COLORS[sev])
        totals = [entry.get("total", 0) for entry in timeline_data]
        ax.plot(x, totals, marker="s", linestyle="--", label="Total",
                color="#6366f1", linewidth=1.5)
    else:
        for severity in SEVERITY_ORDER:
            values = [entry["by_severity"].get(severity, 0) for entry in timeline_data]
            ax.plot(x, values, marker="o", label=severity.capitalize(),
                    color=SEVERITY_COLORS[severity])

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("Count")
    ax.set_title("Vulnerability Trend Over Time", fontsize=13)
    ax.legend()
    ax.grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 4. top5_hosts  (was: host_bar_chart — now limited to top 5)
# ---------------------------------------------------------------------------

def host_bar_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "technical",
    limit: int = 10,
) -> str:
    """
    Horizontal stacked bar chart — vulnerability counts per host.

    Audience behaviour:
      executive   — top 5 hosts, total count only
      management  — top 10, critical+high breakdown
      technical   — top 20, full severity stack

    Returns base64-encoded PNG.
    """
    if audience == "executive":
        limit = 5
    elif audience == "management":
        limit = 10
    else:
        limit = 20

    host_counts: dict[str, dict[str, int]] = {}
    for v in vulnerabilities:
        host = v.affected_host or v.affected_ip or "N/A"
        if host not in host_counts:
            host_counts[host] = {s: 0 for s in SEVERITY_ORDER}
        host_counts[host][v.risk_level] = host_counts[host].get(v.risk_level, 0) + 1

    if not host_counts:
        return ""

    sorted_hosts = sorted(
        host_counts.items(), key=lambda kv: sum(kv[1].values()), reverse=True
    )[:limit]
    hosts = [h for h, _ in sorted_hosts]

    fig, ax = plt.subplots(figsize=(8, max(4, len(hosts) * 0.4 + 1)))

    if audience == "executive":
        totals = [sum(host_counts[h].values()) for h in hosts]
        ax.barh(hosts, totals, color="#6366f1")
        for i, v in enumerate(totals):
            ax.text(v + 0.1, i, str(v), va="center", fontsize=9)
    else:
        severities = ["critical", "high"] if audience == "management" else SEVERITY_ORDER
        bottom = [0] * len(hosts)
        for severity in severities:
            values = [host_counts[h].get(severity, 0) for h in hosts]
            ax.barh(hosts, values, left=bottom,
                    color=SEVERITY_COLORS[severity], label=severity.capitalize())
            bottom = [b + v for b, v in zip(bottom, values)]
        ax.legend(loc="lower right")

    ax.set_xlabel("Number of Vulnerabilities")
    ax.set_title(f"Top {limit} Hosts by Vulnerability Count", fontsize=13)
    ax.invert_yaxis()
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 5. risk_matrix  (FIXED: 5×5 heatmap using likelihood × impact)
# ---------------------------------------------------------------------------

def risk_matrix_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "technical",
) -> str:
    """
    5×5 risk heatmap — likelihood (Y, 1-5) × impact (X, 1-5).

    Each cell shows the count of vulnerabilities with that combination.
    Uses effective_likelihood() / effective_impact() so derived values
    fill in when parsers don't provide explicit axes.

    Returns base64-encoded PNG.
    """
    if not vulnerabilities:
        return ""

    # Build 5×5 count matrix indexed [likelihood-1][impact-1]
    matrix = np.zeros((5, 5), dtype=int)
    for v in vulnerabilities:
        lik = v.effective_likelihood() - 1   # 0-4
        imp = v.effective_impact() - 1       # 0-4
        lik = max(0, min(4, lik))
        imp = max(0, min(4, imp))
        matrix[lik][imp] += 1

    fig, ax = plt.subplots(figsize=(7, 6))

    # Background colour zones: low (green) → critical (red)
    # Zone colour determined by lik*imp product
    bg = np.zeros((5, 5))
    for r in range(5):
        for c in range(5):
            bg[r][c] = (r + 1) * (c + 1)   # 1-25

    ax.imshow(bg, cmap="RdYlGn_r", vmin=1, vmax=25, aspect="auto", origin="lower",
              alpha=0.5)

    # Overlay count annotations
    for r in range(5):
        for c in range(5):
            count = matrix[r][c]
            if count > 0:
                ax.text(c, r, str(count), ha="center", va="center",
                        fontsize=11, fontweight="bold", color="#1e293b")

    labels = ["1\nVery Low", "2\nLow", "3\nMedium", "4\nHigh", "5\nVery High"]
    ax.set_xticks(range(5))
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_yticks(range(5))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Impact", fontsize=11)
    ax.set_ylabel("Likelihood", fontsize=11)
    ax.set_title("Risk Matrix (Likelihood × Impact)", fontsize=13)

    # Grid lines between cells
    for i in range(6):
        ax.axhline(i - 0.5, color="white", linewidth=1)
        ax.axvline(i - 0.5, color="white", linewidth=1)

    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 6. vulns_by_category
# ---------------------------------------------------------------------------

def vulns_by_category_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "technical",
) -> str:
    """
    Horizontal bar chart — vulnerability counts by category
    (CWE-ID, OWASP Top 10, MASVS control, etc.).

    Vulnerabilities without a category are grouped under "Uncategorized".

    Returns base64-encoded PNG.
    """
    cat_counts: Counter = Counter()
    for v in vulnerabilities:
        cat = v.category.strip() if v.category else "Uncategorized"
        cat_counts[cat] += 1

    if not cat_counts:
        return ""

    limit = 5 if audience == "executive" else (10 if audience == "management" else 20)
    sorted_cats = cat_counts.most_common(limit)
    categories = [c for c, _ in sorted_cats]
    counts = [n for _, n in sorted_cats]

    fig, ax = plt.subplots(figsize=(8, max(4, len(categories) * 0.4 + 1)))
    bars = ax.barh(categories, counts, color="#6366f1")
    ax.set_xlabel("Count")
    ax.set_title(f"Vulnerabilities by Category (Top {limit})", fontsize=13)
    ax.invert_yaxis()

    if audience != "executive":
        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    str(count), va="center", fontsize=9)

    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 7. remediation_effort
# ---------------------------------------------------------------------------

def remediation_effort_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "technical",
) -> str:
    """
    Grouped bar chart — vulnerability counts by effort level (low/medium/high)
    broken down by severity.

    Uses effective_effort_level() so all vulns produce a value.

    Returns base64-encoded PNG.
    """
    effort_order = ["low", "medium", "high"]

    # Build: effort → severity → count
    data: dict[str, dict[str, int]] = {e: {s: 0 for s in SEVERITY_ORDER}
                                        for e in effort_order}
    for v in vulnerabilities:
        effort = v.effective_effort_level()
        if effort in data:
            data[effort][v.risk_level] = data[effort].get(v.risk_level, 0) + 1

    if not any(sum(data[e].values()) for e in effort_order):
        return ""

    x = np.arange(len(effort_order))
    severities = SEVERITY_ORDER if audience == "technical" else ["critical", "high", "medium"]
    width = 0.15
    n = len(severities)

    fig, ax = plt.subplots(figsize=(9, 5))
    for i, sev in enumerate(severities):
        counts = [data[e][sev] for e in effort_order]
        offset = (i - n / 2 + 0.5) * width
        ax.bar(x + offset, counts, width, label=sev.capitalize(),
               color=SEVERITY_COLORS[sev])

    ax.set_xticks(x)
    ax.set_xticklabels([e.capitalize() for e in effort_order])
    ax.set_xlabel("Remediation Effort")
    ax.set_ylabel("Count")
    ax.set_title("Vulnerabilities by Remediation Effort", fontsize=13)
    ax.legend()
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 8. fixed_vs_open
# ---------------------------------------------------------------------------

def fixed_vs_open_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "management",
) -> str:
    """
    Stacked / grouped bar showing vuln_status distribution.
    Statuses: open, fixed, accepted, retest.

    Audience behaviour:
      executive   — open vs fixed only (2-bar)
      management  — all 4 statuses, stacked
      technical   — all 4 statuses, grouped

    Returns base64-encoded PNG.
    """
    status_counts: Counter = Counter(v.vuln_status for v in vulnerabilities)
    if not status_counts:
        return ""

    STATUS_COLORS = {
        "open": "#dc2626",
        "fixed": "#22c55e",
        "accepted": "#d97706",
        "retest": "#6366f1",
    }

    if audience == "executive":
        statuses = ["open", "fixed"]
    else:
        statuses = ["open", "fixed", "accepted", "retest"]

    labels = [s.capitalize() for s in statuses]
    counts = [status_counts.get(s, 0) for s in statuses]
    colors = [STATUS_COLORS[s] for s in statuses]
    total = sum(counts)

    fig, ax = plt.subplots(figsize=(7, 5))

    if audience == "technical":
        # Grouped bars
        x = np.arange(len(statuses))
        bars = ax.bar(x, counts, color=colors, width=0.5)
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        for bar, count in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.2,
                    str(count), ha="center", va="bottom", fontsize=9)
    else:
        # Horizontal stacked bar
        left = 0
        for s, count, color in zip(statuses, counts, colors):
            ax.barh(["Status"], [count], left=left, color=color,
                    label=f"{s.capitalize()} ({count})")
            if count > 0 and total > 0:
                pct = count / total * 100
                mid = left + count / 2
                ax.text(mid, 0, f"{pct:.0f}%", ha="center", va="center",
                        fontsize=9, color="white", fontweight="bold")
            left += count
        ax.legend(loc="upper right")
        ax.set_yticks([])

    ax.set_title("Vulnerability Status Distribution", fontsize=13)
    ax.set_xlabel("Count")
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 9. cvss_breakdown  (radar chart over CVSS v3 vector components)
# ---------------------------------------------------------------------------

_CVSS_METRIC_MAX = {
    "AV": 4, "AC": 2, "PR": 3, "UI": 2,
    "C": 3, "I": 3, "A": 3,
}
_CVSS_METRIC_VALUES: dict[str, dict[str, int]] = {
    "AV": {"N": 4, "A": 3, "L": 2, "P": 1},
    "AC": {"L": 2, "H": 1},
    "PR": {"N": 3, "L": 2, "H": 1},
    "UI": {"N": 2, "R": 1},
    "C":  {"H": 3, "L": 2, "N": 1},
    "I":  {"H": 3, "L": 2, "N": 1},
    "A":  {"H": 3, "L": 2, "N": 1},
}
_CVSS_LABELS = {
    "AV": "Attack\nVector", "AC": "Attack\nComplexity",
    "PR": "Privileges\nReq.", "UI": "User\nInteraction",
    "C": "Confidentiality", "I": "Integrity", "A": "Availability",
}


def _parse_cvss_vector(vector: str) -> dict[str, float]:
    """
    Parse a CVSS v3 vector string and return metric → normalised value (0-1).
    Returns empty dict if the vector cannot be parsed.
    """
    metrics: dict[str, float] = {}
    # Strip prefix
    vector = re.sub(r"^CVSS:[0-9.]+/", "", vector)
    parts = vector.split("/")
    for part in parts:
        if ":" not in part:
            continue
        metric, value = part.split(":", 1)
        if metric in _CVSS_METRIC_VALUES and value in _CVSS_METRIC_VALUES[metric]:
            raw = _CVSS_METRIC_VALUES[metric][value]
            metrics[metric] = raw / _CVSS_METRIC_MAX[metric]
    return metrics


def cvss_breakdown_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "technical",
) -> str:
    """
    Radar chart showing average CVSS v3 vector component scores.
    Only vulnerabilities with a non-empty cvss_vector are included.

    Returns base64-encoded PNG.
    """
    parsed: list[dict[str, float]] = []
    for v in vulnerabilities:
        if v.cvss_vector:
            m = _parse_cvss_vector(v.cvss_vector)
            if m:
                parsed.append(m)

    if not parsed:
        return ""

    metric_keys = list(_CVSS_METRIC_MAX.keys())
    # Average each metric across all parsed vectors
    avgs = []
    for mk in metric_keys:
        vals = [p[mk] for p in parsed if mk in p]
        avgs.append(sum(vals) / len(vals) if vals else 0.0)

    # Radar requires closing the loop
    n = len(metric_keys)
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False).tolist()
    angles += angles[:1]
    avgs_plot = avgs + avgs[:1]

    fig, ax = plt.subplots(figsize=(6, 6), subplot_kw={"polar": True})
    ax.plot(angles, avgs_plot, "o-", linewidth=2, color="#6366f1")
    ax.fill(angles, avgs_plot, alpha=0.25, color="#6366f1")
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(
        [_CVSS_LABELS.get(mk, mk) for mk in metric_keys], fontsize=8
    )
    ax.set_ylim(0, 1)
    ax.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax.set_yticklabels(["0.25", "0.5", "0.75", "1.0"], fontsize=7)

    n_shown = len(parsed)
    ax.set_title(
        f"CVSS Vector Breakdown\n(avg of {n_shown} vulns with vector)",
        fontsize=12, pad=20,
    )
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 10. epss_distribution
# ---------------------------------------------------------------------------

def epss_distribution_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "technical",
) -> str:
    """
    Histogram of EPSS scores (0-1) for all vulnerabilities with a score.

    Audience behaviour:
      executive   — 5 buckets, no Y label
      management  — 10 buckets
      technical   — 20 buckets with density line

    Returns base64-encoded PNG.
    """
    scores = [v.epss_score for v in vulnerabilities if v.epss_score is not None]
    if not scores:
        return ""

    bins = 5 if audience == "executive" else (10 if audience == "management" else 20)

    fig, ax = plt.subplots(figsize=(7, 5))
    n, bin_edges, patches = ax.hist(scores, bins=bins, range=(0.0, 1.0),
                                     color="#6366f1", edgecolor="white", alpha=0.85)

    # Colour buckets by risk zone
    for patch, left_edge in zip(patches, bin_edges[:-1]):
        mid = left_edge + (bin_edges[1] - bin_edges[0]) / 2
        if mid < 0.1:
            patch.set_facecolor(SEVERITY_COLORS["info"])
        elif mid < 0.3:
            patch.set_facecolor(SEVERITY_COLORS["low"])
        elif mid < 0.6:
            patch.set_facecolor(SEVERITY_COLORS["medium"])
        elif mid < 0.85:
            patch.set_facecolor(SEVERITY_COLORS["high"])
        else:
            patch.set_facecolor(SEVERITY_COLORS["critical"])

    ax.set_xlabel("EPSS Score (Exploit Probability)")
    if audience != "executive":
        ax.set_ylabel("Number of Vulnerabilities")
    ax.set_title("EPSS Score Distribution", fontsize=13)
    ax.set_xlim(0.0, 1.0)
    ax.grid(True, axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    return _fig_to_base64(fig)


# ---------------------------------------------------------------------------
# 11. vulns_per_host  (grouped: host × severity)
# ---------------------------------------------------------------------------

def vulns_per_host_chart(
    vulnerabilities: list,
    audience: AudienceLevel = "technical",
) -> str:
    """
    Grouped bar chart — severity breakdown per host (top N hosts).

    Audience behaviour:
      executive   — top 5, critical only
      management  — top 10, critical + high
      technical   — top 15, all severities

    Returns base64-encoded PNG.
    """
    limit = 5 if audience == "executive" else (10 if audience == "management" else 15)
    severities = (
        ["critical"] if audience == "executive"
        else (["critical", "high"] if audience == "management"
              else SEVERITY_ORDER)
    )

    host_sev: dict[str, dict[str, int]] = defaultdict(lambda: {s: 0 for s in SEVERITY_ORDER})
    for v in vulnerabilities:
        host = v.affected_host or v.affected_ip or "N/A"
        host_sev[host][v.risk_level] += 1

    if not host_sev:
        return ""

    sorted_hosts = sorted(
        host_sev.items(), key=lambda kv: sum(kv[1].values()), reverse=True
    )[:limit]
    hosts = [h for h, _ in sorted_hosts]

    x = np.arange(len(hosts))
    n = len(severities)
    width = 0.8 / n

    fig, ax = plt.subplots(figsize=(max(8, len(hosts) * 0.8 + 2), 5))
    for i, sev in enumerate(severities):
        counts = [host_sev[h][sev] for h in hosts]
        offset = (i - n / 2 + 0.5) * width
        ax.bar(x + offset, counts, width, label=sev.capitalize(),
               color=SEVERITY_COLORS[sev])

    ax.set_xticks(x)
    ax.set_xticklabels(hosts, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("Count")
    ax.set_title(f"Vulnerabilities per Host (Top {limit})", fontsize=13)
    ax.legend()
    ax.grid(True, axis="y", linestyle="--", alpha=0.3)
    fig.tight_layout()
    return _fig_to_base64(fig)
