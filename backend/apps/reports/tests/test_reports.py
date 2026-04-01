"""
Tests for the reports app.
Covers: ReportExport model, XML generation, HTML template rendering,
ReportGenerator helpers, and the _make_filename logic.

WeasyPrint (PDF) is mocked to avoid requiring a browser-rendering engine
in the test environment.
"""

import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

import pytest

from apps.reports.models import ReportExport
from apps.vulnerabilities.models import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_export(subproject, admin_user, fmt=ReportExport.Format.XML, options=None):
    return ReportExport.objects.create(
        subproject=subproject,
        format=fmt,
        generated_by=admin_user,
        options=options or {},
    )


# ---------------------------------------------------------------------------
# ReportExport model
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestReportExportModel:
    def test_str_representation(self, subproject, admin_user):
        exp = _make_export(subproject, admin_user)
        assert "xml" in str(exp).lower() or "Report" in str(exp)

    def test_initial_status_is_pending(self, subproject, admin_user):
        exp = _make_export(subproject, admin_user)
        assert exp.status == ReportExport.Status.PENDING

    def test_options_default_is_dict(self, subproject, admin_user):
        exp = _make_export(subproject, admin_user)
        assert isinstance(exp.options, dict)

    def test_format_choices(self, subproject, admin_user):
        for fmt in (ReportExport.Format.PDF, ReportExport.Format.HTML, ReportExport.Format.XML):
            exp = _make_export(subproject, admin_user, fmt=fmt)
            assert exp.format == fmt


# ---------------------------------------------------------------------------
# ReportGenerator — XML generation
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestXMLGeneration:
    def _generate_and_read_xml(self, subproject, admin_user, vulnerability=None, options=None):
        from apps.reports.generator import ReportGenerator
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.XML, options=options)
        gen = ReportGenerator(exp.pk)
        gen.generate()
        # Access file directly from generator (already saved to storage)
        return gen.export.file.read().decode("utf-8")

    def test_xml_contains_vulnerabilities(self, subproject, admin_user, vulnerability):
        xml_content = self._generate_and_read_xml(subproject, admin_user, vulnerability)
        assert vulnerability.title in xml_content

    def test_xml_structure_valid(self, subproject, admin_user, vulnerability):
        xml_content = self._generate_and_read_xml(subproject, admin_user, vulnerability)
        root = ET.fromstring(xml_content)
        assert root.tag == "report"
        vulns_el = root.find("vulnerabilities")
        assert vulns_el is not None
        assert int(vulns_el.get("count")) == 1

    def test_xml_vuln_fields_present(self, subproject, admin_user, vulnerability):
        xml_content = self._generate_and_read_xml(subproject, admin_user, vulnerability)
        root = ET.fromstring(xml_content)
        vuln_el = root.find(".//vulnerability")
        assert vuln_el is not None
        assert vuln_el.findtext("title") == vulnerability.title
        assert vuln_el.findtext("risk_level") == vulnerability.risk_level
        assert vuln_el.findtext("affected_host") == vulnerability.affected_host

    def test_xml_respects_status_filter(self, subproject, admin_user):
        Vulnerability.objects.create(subproject=subproject, title="Open", risk_level="high", vuln_status="open")
        Vulnerability.objects.create(subproject=subproject, title="Fixed", risk_level="high", vuln_status="fixed")
        xml_content = self._generate_and_read_xml(subproject, admin_user,
                                                   options={"vuln_status": ["open"]})
        root = ET.fromstring(xml_content)
        assert int(root.find("vulnerabilities").get("count")) == 1

    def test_xml_respects_severity_filter(self, subproject, admin_user):
        Vulnerability.objects.create(subproject=subproject, title="Critical v", risk_level="critical")
        Vulnerability.objects.create(subproject=subproject, title="Low v", risk_level="low")
        xml_content = self._generate_and_read_xml(subproject, admin_user,
                                                   options={"risk_levels": ["critical"]})
        root = ET.fromstring(xml_content)
        assert int(root.find("vulnerabilities").get("count")) == 1
        assert root.find(".//vulnerability/title").text == "Critical v"

    def test_empty_subproject_xml(self, subproject, admin_user):
        xml_content = self._generate_and_read_xml(subproject, admin_user)
        root = ET.fromstring(xml_content)
        assert int(root.find("vulnerabilities").get("count")) == 0


# ---------------------------------------------------------------------------
# ReportGenerator — HTML generation
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestHTMLGeneration:
    def _generate_and_read_html(self, subproject, admin_user, vulnerability=None):
        from apps.reports.generator import ReportGenerator
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.HTML)
        gen = ReportGenerator(exp.pk)
        gen.generate()
        return gen.export.file.read().decode("utf-8")

    def test_html_generates_without_error(self, subproject, admin_user, vulnerability):
        html = self._generate_and_read_html(subproject, admin_user, vulnerability)
        assert len(html) > 100

    def test_html_contains_vuln_title(self, subproject, admin_user, vulnerability):
        html = self._generate_and_read_html(subproject, admin_user, vulnerability)
        assert vulnerability.title in html

    def test_html_contains_project_info(self, subproject, admin_user):
        html = self._generate_and_read_html(subproject, admin_user)
        assert subproject.project.client_name in html


# ---------------------------------------------------------------------------
# ReportGenerator — PDF generation (mocked WeasyPrint)
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestPDFGeneration:
    def test_pdf_generates_without_error(self, subproject, admin_user):
        import sys
        from apps.reports.generator import ReportGenerator

        # WeasyPrint has heavy system deps (cairo, pango); mock the whole module.
        mock_weasyprint = MagicMock()
        mock_weasyprint.HTML.return_value.write_pdf.return_value = b"%PDF-1.4 fake"

        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.PDF)
        gen = ReportGenerator(exp.pk)

        with patch.dict(sys.modules, {"weasyprint": mock_weasyprint}):
            gen.generate()

        assert gen.export.status == ReportExport.Status.DONE


# ---------------------------------------------------------------------------
# ReportGenerator — generate() dispatches and updates status
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestGenerateDispatch:
    def test_generate_xml_sets_status_done(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.XML)
        gen = ReportGenerator(exp.pk)
        gen.generate()
        assert gen.export.status == ReportExport.Status.DONE
        assert gen.export.completed_at is not None

    def test_generate_html_sets_status_done(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.HTML)
        gen = ReportGenerator(exp.pk)
        gen.generate()
        assert gen.export.status == ReportExport.Status.DONE


# ---------------------------------------------------------------------------
# ReportGenerator — _make_filename
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestMakeFilename:
    def test_filename_contains_pk(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.XML)
        gen = ReportGenerator(exp.pk)
        filename = gen._make_filename("xml")
        assert str(exp.pk) in filename

    def test_filename_has_correct_extension(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.XML)
        gen = ReportGenerator(exp.pk)
        assert gen._make_filename("xml").endswith(".xml")
        assert gen._make_filename("pdf").endswith(".pdf")
        assert gen._make_filename("html").endswith(".html")

    def test_filename_has_no_path_prefix(self, subproject, admin_user):
        """upload_to handles the directory; filename must not include 'reports/'."""
        from apps.reports.generator import ReportGenerator
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.XML)
        gen = ReportGenerator(exp.pk)
        filename = gen._make_filename("xml")
        assert "/" not in filename

    def test_special_chars_sanitized(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        subproject.project.title = "Test / Project: 2025!"
        subproject.project.save()
        exp = _make_export(subproject, admin_user, fmt=ReportExport.Format.XML)
        gen = ReportGenerator(exp.pk)
        filename = gen._make_filename("xml")
        assert "/" not in filename
        assert ":" not in filename
        assert "!" not in filename


# ---------------------------------------------------------------------------
# _get_vulnerabilities filtering
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestGetVulnerabilities:
    def test_returns_all_by_default(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        Vulnerability.objects.create(subproject=subproject, title="V1", risk_level="high")
        Vulnerability.objects.create(subproject=subproject, title="V2", risk_level="low")
        exp = _make_export(subproject, admin_user)
        gen = ReportGenerator(exp.pk)
        assert len(gen._get_vulnerabilities()) == 2

    def test_filters_by_vuln_status(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        Vulnerability.objects.create(subproject=subproject, title="Open", risk_level="high", vuln_status="open")
        Vulnerability.objects.create(subproject=subproject, title="Fixed", risk_level="high", vuln_status="fixed")
        exp = _make_export(subproject, admin_user, options={"vuln_status": ["open"]})
        gen = ReportGenerator(exp.pk)
        results = gen._get_vulnerabilities()
        assert len(results) == 1
        assert results[0].title == "Open"

    def test_filters_by_risk_level(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        Vulnerability.objects.create(subproject=subproject, title="Crit", risk_level="critical")
        Vulnerability.objects.create(subproject=subproject, title="Low", risk_level="low")
        exp = _make_export(subproject, admin_user, options={"risk_levels": ["critical"]})
        gen = ReportGenerator(exp.pk)
        results = gen._get_vulnerabilities()
        assert len(results) == 1
        assert results[0].title == "Crit"

    def test_ordered_by_risk_score_desc(self, subproject, admin_user):
        from apps.reports.generator import ReportGenerator
        Vulnerability.objects.create(subproject=subproject, title="High score", risk_level="high", cvss_score=9.0)
        Vulnerability.objects.create(subproject=subproject, title="Low score", risk_level="low", cvss_score=2.0)
        exp = _make_export(subproject, admin_user)
        gen = ReportGenerator(exp.pk)
        results = gen._get_vulnerabilities()
        assert results[0].title == "High score"
