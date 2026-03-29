"""
Unit and integration tests for the vulnerabilities app.
Covers: Vulnerability model, ScanImport, deduplication, diff, timeline, risk scoring.
"""

import pytest
from django.utils import timezone

from apps.vulnerabilities.deduplication import (
    NormalizedVulnerability,
    VulnDiff,
    build_timeline,
    compute_diff,
    deduplicate_and_save,
)
from apps.vulnerabilities.models import ScanImport, Vulnerability


# ---------------------------------------------------------------------------
# Vulnerability model
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestVulnerabilityModel:
    def test_str_representation(self, vulnerability):
        expected = f"[{vulnerability.risk_level.upper()}] {vulnerability.title} @ {vulnerability.affected_host}"
        assert str(vulnerability) == expected

    def test_dedup_key(self, vulnerability):
        key = vulnerability.dedup_key
        host = (vulnerability.affected_ip or vulnerability.affected_host).lower().strip()
        port = str(vulnerability.affected_port) if vulnerability.affected_port else ""
        assert key == (
            vulnerability.title.lower().strip(),
            host,
            port,
        )

    def test_compute_risk_score_cvss_only(self, subproject):
        vuln = Vulnerability(
            subproject=subproject,
            title="Test",
            cvss_score=8.0,
            epss_score=None,
        )
        score = vuln.compute_risk_score()
        assert score == round(8.0 * 0.7, 2)

    def test_compute_risk_score_both(self, subproject):
        vuln = Vulnerability(
            subproject=subproject,
            title="Test",
            cvss_score=8.0,
            epss_score=0.5,
        )
        score = vuln.compute_risk_score()
        expected = round((8.0 * 0.7) + (0.5 * 10 * 0.3), 2)
        assert score == expected

    def test_risk_score_capped_at_10(self, subproject):
        vuln = Vulnerability(
            subproject=subproject,
            title="Test",
            cvss_score=10.0,
            epss_score=1.0,
        )
        score = vuln.compute_risk_score()
        assert score <= 10.0

    def test_risk_score_auto_computed_on_save(self, subproject):
        vuln = Vulnerability.objects.create(
            subproject=subproject,
            title="Auto scored vuln",
            cvss_score=7.5,
            epss_score=0.3,
            risk_level=Vulnerability.RiskLevel.HIGH,
        )
        assert vuln.risk_score is not None
        assert vuln.risk_score == vuln.compute_risk_score()

    def test_risk_score_null_without_scores(self, subproject):
        vuln = Vulnerability.objects.create(
            subproject=subproject,
            title="No scores",
            risk_level=Vulnerability.RiskLevel.LOW,
        )
        assert vuln.risk_score is None

    def test_sources_default_is_list(self, subproject):
        vuln = Vulnerability.objects.create(
            subproject=subproject,
            title="Src test",
            risk_level=Vulnerability.RiskLevel.LOW,
        )
        assert vuln.sources == []
        assert isinstance(vuln.sources, list)

    def test_is_recurring_defaults_false(self, subproject):
        vuln = Vulnerability.objects.create(
            subproject=subproject,
            title="Recur test",
            risk_level=Vulnerability.RiskLevel.LOW,
        )
        assert vuln.is_recurring is False


# ---------------------------------------------------------------------------
# ScanImport model
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestScanImportModel:
    def test_str_representation(self, scan_import):
        assert scan_import.tool in str(scan_import)
        assert scan_import.original_filename in str(scan_import)

    def test_mark_done(self, scan_import):
        scan_import.mark_done(vuln_count=42)
        assert scan_import.status == ScanImport.Status.DONE
        assert scan_import.vulnerability_count == 42
        assert scan_import.processed_at is not None

    def test_mark_failed(self, scan_import):
        scan_import.mark_failed("Parse error: unexpected EOF")
        assert scan_import.status == ScanImport.Status.FAILED
        assert "Parse error" in scan_import.error_message
        assert scan_import.processed_at is not None

    def test_initial_status_is_pending(self, scan_import):
        assert scan_import.status == ScanImport.Status.PENDING


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestDeduplication:
    def _make_norm(self, title="SQLi", host="10.0.0.1", port=443, source="nmap"):
        return NormalizedVulnerability(
            title=title,
            description="Test vuln",
            affected_host=host,
            affected_port=port,
            risk_level="high",
            source=source,
        )

    def test_new_vuln_is_created(self, subproject):
        norm = self._make_norm()
        results = deduplicate_and_save([norm], subproject.pk)
        assert len(results) == 1
        assert Vulnerability.objects.filter(subproject=subproject).count() == 1

    def test_duplicate_is_merged_not_created(self, subproject):
        norm1 = self._make_norm(source="nmap")
        norm2 = self._make_norm(source="nikto")  # same key, different source
        deduplicate_and_save([norm1], subproject.pk)
        deduplicate_and_save([norm2], subproject.pk)
        assert Vulnerability.objects.filter(subproject=subproject).count() == 1

    def test_sources_list_extended_on_merge(self, subproject):
        norm1 = self._make_norm(source="nmap")
        norm2 = self._make_norm(source="nikto")
        deduplicate_and_save([norm1], subproject.pk)
        deduplicate_and_save([norm2], subproject.pk)
        vuln = Vulnerability.objects.get(subproject=subproject)
        assert "nmap" in vuln.sources
        assert "nikto" in vuln.sources

    def test_duplicate_source_not_added_twice(self, subproject):
        norm1 = self._make_norm(source="nmap")
        norm2 = self._make_norm(source="nmap")
        deduplicate_and_save([norm1], subproject.pk)
        deduplicate_and_save([norm2], subproject.pk)
        vuln = Vulnerability.objects.get(subproject=subproject)
        assert vuln.sources.count("nmap") == 1

    def test_different_host_creates_new(self, subproject):
        norm1 = self._make_norm(host="10.0.0.1")
        norm2 = self._make_norm(host="10.0.0.2")
        deduplicate_and_save([norm1, norm2], subproject.pk)
        assert Vulnerability.objects.filter(subproject=subproject).count() == 2

    def test_different_port_creates_new(self, subproject):
        norm1 = self._make_norm(port=80)
        norm2 = self._make_norm(port=443)
        deduplicate_and_save([norm1, norm2], subproject.pk)
        assert Vulnerability.objects.filter(subproject=subproject).count() == 2

    def test_cvss_set_on_first_source(self, subproject):
        norm = self._make_norm()
        norm.cvss_score = 8.5
        results = deduplicate_and_save([norm], subproject.pk)
        assert results[0].cvss_score == 8.5

    def test_cvss_not_overwritten_on_merge(self, subproject):
        norm1 = self._make_norm(source="nmap")
        norm1.cvss_score = 8.0
        norm2 = self._make_norm(source="nikto")
        norm2.cvss_score = 5.0
        deduplicate_and_save([norm1], subproject.pk)
        deduplicate_and_save([norm2], subproject.pk)
        vuln = Vulnerability.objects.get(subproject=subproject)
        assert vuln.cvss_score == 8.0  # first value preserved

    def test_empty_input_returns_empty(self, subproject):
        results = deduplicate_and_save([], subproject.pk)
        assert results == []


# ---------------------------------------------------------------------------
# Diff between SubProjects
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestVulnDiff:
    def _make_vuln(self, subproject, title="SQLi", host="10.0.0.1", port=80, level="high"):
        return Vulnerability.objects.create(
            subproject=subproject,
            title=title,
            affected_host=host,
            affected_port=port,
            risk_level=level,
        )

    def test_new_vuln_detected(self, project, admin_user):
        from apps.projects.models import SubProject
        from datetime import date
        sp1 = SubProject.objects.create(project=project, created_by=admin_user, title="SP1", scan_date=date(2025, 1, 1))
        sp2 = SubProject.objects.create(project=project, created_by=admin_user, title="SP2", scan_date=date(2025, 2, 1))
        self._make_vuln(sp2, title="New vuln")
        diff = compute_diff(sp2.pk, sp1.pk)
        assert len(diff.new) == 1
        assert diff.new[0].title == "New vuln"

    def test_fixed_vuln_detected(self, project, admin_user):
        from apps.projects.models import SubProject
        from datetime import date
        sp1 = SubProject.objects.create(project=project, created_by=admin_user, title="SP1", scan_date=date(2025, 1, 1))
        sp2 = SubProject.objects.create(project=project, created_by=admin_user, title="SP2", scan_date=date(2025, 2, 1))
        self._make_vuln(sp1, title="Fixed vuln")  # only in sp1
        diff = compute_diff(sp2.pk, sp1.pk)
        assert len(diff.fixed) == 1
        assert diff.fixed[0].title == "Fixed vuln"

    def test_persistent_vuln_detected(self, project, admin_user):
        from apps.projects.models import SubProject
        from datetime import date
        sp1 = SubProject.objects.create(project=project, created_by=admin_user, title="SP1", scan_date=date(2025, 1, 1))
        sp2 = SubProject.objects.create(project=project, created_by=admin_user, title="SP2", scan_date=date(2025, 2, 1))
        self._make_vuln(sp1, title="Persistent", host="10.0.0.1", port=80, level="high")
        self._make_vuln(sp2, title="Persistent", host="10.0.0.1", port=80, level="high")
        diff = compute_diff(sp2.pk, sp1.pk)
        assert len(diff.persistent) == 1
        # is_recurring should be set to True
        vuln = Vulnerability.objects.get(subproject=sp2, title="Persistent")
        assert vuln.is_recurring is True

    def test_changed_severity_detected(self, project, admin_user):
        from apps.projects.models import SubProject
        from datetime import date
        sp1 = SubProject.objects.create(project=project, created_by=admin_user, title="SP1", scan_date=date(2025, 1, 1))
        sp2 = SubProject.objects.create(project=project, created_by=admin_user, title="SP2", scan_date=date(2025, 2, 1))
        self._make_vuln(sp1, title="Changed", host="10.0.0.1", port=80, level="medium")
        self._make_vuln(sp2, title="Changed", host="10.0.0.1", port=80, level="high")
        diff = compute_diff(sp2.pk, sp1.pk)
        assert len(diff.changed) == 1

    def test_empty_subprojects_return_empty_diff(self, project, admin_user):
        from apps.projects.models import SubProject
        from datetime import date
        sp1 = SubProject.objects.create(project=project, created_by=admin_user, title="SP1", scan_date=date(2025, 1, 1))
        sp2 = SubProject.objects.create(project=project, created_by=admin_user, title="SP2", scan_date=date(2025, 2, 1))
        diff = compute_diff(sp2.pk, sp1.pk)
        assert diff.new == []
        assert diff.fixed == []
        assert diff.persistent == []
        assert diff.changed == []


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestTimeline:
    def test_single_subproject_timeline(self, project, subproject, vulnerability):
        timeline = build_timeline(project.pk)
        assert len(timeline) == 1
        entry = timeline[0]
        assert entry["subproject_id"] == subproject.pk
        assert entry["total"] == 1
        assert entry["new"] == 1  # first subproject, all vulns are "new"

    def test_timeline_severity_counts(self, project, subproject):
        Vulnerability.objects.create(
            subproject=subproject,
            title="Critical vuln",
            risk_level=Vulnerability.RiskLevel.CRITICAL,
        )
        Vulnerability.objects.create(
            subproject=subproject,
            title="Low vuln",
            risk_level=Vulnerability.RiskLevel.LOW,
        )
        timeline = build_timeline(project.pk)
        counts = timeline[0]["by_severity"]
        assert counts["critical"] == 1
        assert counts["low"] == 1

    def test_timeline_ordered_by_scan_date(self, project, admin_user):
        from apps.projects.models import SubProject
        from datetime import date
        sp1 = SubProject.objects.create(project=project, created_by=admin_user, title="SP1", scan_date=date(2025, 1, 1))
        sp2 = SubProject.objects.create(project=project, created_by=admin_user, title="SP2", scan_date=date(2025, 3, 1))
        sp3 = SubProject.objects.create(project=project, created_by=admin_user, title="SP3", scan_date=date(2025, 2, 1))
        timeline = build_timeline(project.pk)
        dates = [t["scan_date"] for t in timeline]
        assert dates == sorted(dates)
