"""
Deduplication and diff logic for vulnerabilities.

Process 1 — Normalizzazione & Deduplicazione:
  - Incoming normalized vulnerabilities are matched against existing ones
    in the same SubProject by (title, affected_host, affected_port).
  - Duplicates are merged: sources list is extended, raw_outputs appended.

Process 2 — Diff tra SubProject:
  - Compares current subproject vulns against previous subproject vulns.
  - Classifies each vulnerability as: NEW, FIXED, PERSISTENT, CHANGED.
  - Sets is_recurring=True for PERSISTENT ones.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from django.db import transaction

if TYPE_CHECKING:
    from .models import Vulnerability


class DiffStatus(str, Enum):
    NEW = "new"
    FIXED = "fixed"
    PERSISTENT = "persistent"
    CHANGED = "changed"


@dataclass
class NormalizedVulnerability:
    """
    Intermediate representation produced by parsers before DB persistence.
    All parsers must return List[NormalizedVulnerability].
    """

    title: str
    description: str = ""
    remediation: str = ""
    affected_host: str = ""
    affected_ip: str = ""
    affected_port: int | None = None
    affected_service: str = ""
    affected_protocol: str = "tcp"
    cve_id: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str = ""
    epss_score: float | None = None
    risk_level: str = "medium"
    evidence_code: str = ""
    source: str = ""  # tool name
    raw_output: str = ""
    nvd_enrichment_status: str = "pending"
    # Chart-support fields (set by parsers when available; derived by generator otherwise)
    category: str = ""          # CWE-ID, OWASP category, MASVS control, etc.
    likelihood: int | None = None   # 1-5
    impact: int | None = None       # 1-5
    effort_level: str = ""      # low / medium / high


@dataclass
class VulnDiff:
    """Result of comparing two SubProjects."""

    new: list[Vulnerability] = field(default_factory=list)
    fixed: list[Vulnerability] = field(default_factory=list)
    persistent: list[Vulnerability] = field(default_factory=list)
    changed: list[Vulnerability] = field(default_factory=list)


def deduplicate_and_save(
    normalized_vulns: list[NormalizedVulnerability],
    subproject_id: int,
    scan_import_id: int | None = None,
) -> list["Vulnerability"]:
    """
    Persist a list of NormalizedVulnerability into the DB.
    Existing vulns with the same (title, host, port) are merged
    instead of duplicated.

    Returns the list of saved Vulnerability objects.
    """
    from .models import Vulnerability

    saved: list[Vulnerability] = []

    with transaction.atomic():
        # Load existing vulns for this subproject as a lookup map
        existing = {
            v.dedup_key: v
            for v in Vulnerability.objects.filter(subproject_id=subproject_id)
        }

        for norm in normalized_vulns:
            host = (norm.affected_ip or norm.affected_host).lower().strip()
            port = str(norm.affected_port) if norm.affected_port else ""
            key = (norm.title.lower().strip(), host, port)

            if key in existing:
                vuln = existing[key]
                # Merge sources
                if norm.source and norm.source not in vuln.sources:
                    vuln.sources.append(norm.source)
                # Append raw output
                if norm.raw_output:
                    vuln.raw_outputs.append(norm.raw_output)
                # Merge CVE lists (union, dedup)
                existing_cves = set(vuln.cve_id or [])
                new_cves = set(norm.cve_id or [])
                merged = sorted(existing_cves | new_cves)
                if merged != sorted(existing_cves):
                    vuln.cve_id = merged
                # Update CVSS/EPSS if not already set
                if vuln.cvss_score is None and norm.cvss_score is not None:
                    vuln.cvss_score = norm.cvss_score
                    vuln.cvss_vector = norm.cvss_vector
                if vuln.epss_score is None and norm.epss_score is not None:
                    vuln.epss_score = norm.epss_score
                vuln.save()
                saved.append(vuln)
            else:
                vuln = Vulnerability(
                    subproject_id=subproject_id,
                    scan_import_id=scan_import_id,
                    title=norm.title,
                    description=norm.description,
                    remediation=norm.remediation,
                    affected_ip=norm.affected_ip,
                    affected_host=norm.affected_host,
                    affected_port=norm.affected_port,
                    affected_service=norm.affected_service,
                    cve_id=list(norm.cve_id) if norm.cve_id else [],
                    cvss_score=norm.cvss_score,
                    cvss_vector=norm.cvss_vector,
                    epss_score=norm.epss_score,
                    risk_level=norm.risk_level,
                    evidence_code=norm.evidence_code,
                    nvd_enrichment_status=norm.nvd_enrichment_status,
                    category=norm.category,
                    likelihood=norm.likelihood,
                    impact=norm.impact,
                    effort_level=norm.effort_level,
                    sources=[norm.source] if norm.source else [],
                    raw_outputs=[norm.raw_output] if norm.raw_output else [],
                )
                vuln.save()
                existing[key] = vuln
                saved.append(vuln)

    return saved


def compute_diff(current_subproject_id: int, previous_subproject_id: int) -> VulnDiff:
    """
    Compare vulnerabilities between two SubProjects.

    Classification:
      NEW        — in current, not in previous
      FIXED      — in previous, not in current
      PERSISTENT — in both, not fixed → mark is_recurring=True
      CHANGED    — in both, risk_level changed
    """
    from .models import Vulnerability

    current_vulns = {
        v.dedup_key: v
        for v in Vulnerability.objects.filter(subproject_id=current_subproject_id)
    }
    previous_vulns = {
        v.dedup_key: v
        for v in Vulnerability.objects.filter(subproject_id=previous_subproject_id)
    }

    diff = VulnDiff()
    to_update: list[Vulnerability] = []

    for key, vuln in current_vulns.items():
        if key not in previous_vulns:
            diff.new.append(vuln)
        else:
            prev = previous_vulns[key]
            if vuln.risk_level != prev.risk_level:
                diff.changed.append(vuln)
            else:
                diff.persistent.append(vuln)
                if not vuln.is_recurring:
                    vuln.is_recurring = True
                    to_update.append(vuln)

    for key, vuln in previous_vulns.items():
        if key not in current_vulns:
            diff.fixed.append(vuln)

    if to_update:
        Vulnerability.objects.bulk_update(to_update, ["is_recurring"])

    return diff


def build_timeline(project_id: int) -> list[dict]:
    """
    Build a timeline of SubProject metrics for a Project.
    Each entry contains aggregated vulnerability counts by severity.
    """
    from apps.projects.models import SubProject
    from .models import Vulnerability

    subprojects = SubProject.objects.filter(project_id=project_id).order_by("scan_date", "created_at")
    timeline: list[dict] = []

    for sp in subprojects:
        vulns = Vulnerability.objects.filter(subproject=sp)
        counts = {level: 0 for level in Vulnerability.RiskLevel.values}
        for v in vulns:
            counts[v.risk_level] += 1

        total = sum(counts.values())
        risk_scores = [v.risk_score for v in vulns if v.risk_score is not None]
        avg_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0

        timeline.append({
            "subproject_id": sp.pk,
            "subproject_title": sp.title,
            "scan_date": sp.scan_date,
            "total": total,
            "by_severity": counts,
            "average_risk_score": avg_risk,
        })

    # Enrich with diff vs previous
    for i, entry in enumerate(timeline):
        if i == 0:
            entry["new"] = entry["total"]
            entry["fixed"] = 0
            entry["persistent"] = 0
        else:
            prev_id = timeline[i - 1]["subproject_id"]
            curr_id = entry["subproject_id"]
            diff = compute_diff(curr_id, prev_id)
            entry["new"] = len(diff.new)
            entry["fixed"] = len(diff.fixed)
            entry["persistent"] = len(diff.persistent)

    return timeline
