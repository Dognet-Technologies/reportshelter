"""
Report generation logic.
Assembles context, renders Jinja2 template, and produces PDF/HTML/XML output.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from django.conf import settings
from django.template.loader import render_to_string

from apps.vulnerabilities.deduplication import build_timeline
from apps.vulnerabilities.models import Vulnerability

from .charts import host_bar_chart, risk_matrix_chart, severity_pie_chart, timeline_chart
from .models import ReportExport


class ReportGenerator:
    """
    Builds reports (PDF, HTML, XML) for a SubProject.

    Usage:
        gen = ReportGenerator(export_id)
        gen.generate()
    """

    def __init__(self, export_id: int) -> None:
        self.export = ReportExport.objects.select_related(
            "subproject__project__organization",
            "generated_by",
        ).get(pk=export_id)
        self.subproject = self.export.subproject
        self.project = self.subproject.project
        self.org = self.project.organization
        self.options: dict = self.export.options

    def generate(self) -> None:
        """Main entry point — dispatches to the appropriate format generator."""
        from django.utils import timezone

        self.export.status = ReportExport.Status.GENERATING
        self.export.save(update_fields=["status"])

        try:
            fmt = self.export.format
            if fmt == ReportExport.Format.PDF:
                self._generate_pdf()
            elif fmt == ReportExport.Format.HTML:
                self._generate_html()
            elif fmt == ReportExport.Format.XML:
                self._generate_xml()
            else:
                raise ValueError(f"Unsupported format: {fmt}")

            self.export.status = ReportExport.Status.DONE
            self.export.completed_at = timezone.now()
            self.export.save(update_fields=["status", "completed_at", "file"])
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Report generation failed for export %s", self.export.pk)
            self.export.status = ReportExport.Status.FAILED
            self.export.error_message = str(exc)
            self.export.save(update_fields=["status", "error_message"])
            raise

    # ------------------------------------------------------------------
    # PDF
    # ------------------------------------------------------------------

    def _generate_pdf(self) -> None:
        from weasyprint import HTML as WP_HTML

        html_str = self._render_html_template()
        pdf_bytes = WP_HTML(string=html_str, base_url=str(settings.BASE_DIR)).write_pdf()

        filename = self._make_filename("pdf")
        self.export.file.save(filename, io.BytesIO(pdf_bytes), save=False)

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def _generate_html(self) -> None:
        html_str = self._render_html_template()
        filename = self._make_filename("html")
        self.export.file.save(filename, io.BytesIO(html_str.encode("utf-8")), save=False)

    # ------------------------------------------------------------------
    # XML
    # ------------------------------------------------------------------

    def _generate_xml(self) -> None:
        vulnerabilities = self._get_vulnerabilities()

        root = ET.Element("report")
        root.set("project", self.project.title)
        root.set("subproject", self.subproject.title)
        root.set("client", self.project.client_name)

        vulns_el = ET.SubElement(root, "vulnerabilities")
        vulns_el.set("count", str(len(vulnerabilities)))

        for v in vulnerabilities:
            vuln_el = ET.SubElement(vulns_el, "vulnerability")
            ET.SubElement(vuln_el, "id").text = str(v.pk)
            ET.SubElement(vuln_el, "title").text = v.title
            ET.SubElement(vuln_el, "risk_level").text = v.risk_level
            ET.SubElement(vuln_el, "status").text = v.vuln_status
            ET.SubElement(vuln_el, "affected_host").text = v.affected_host
            ET.SubElement(vuln_el, "affected_port").text = v.affected_port
            ET.SubElement(vuln_el, "cve_id").text = v.cve_id
            if v.cvss_score is not None:
                ET.SubElement(vuln_el, "cvss_score").text = str(v.cvss_score)
            ET.SubElement(vuln_el, "description").text = v.description
            ET.SubElement(vuln_el, "remediation").text = v.remediation

        tree = ET.ElementTree(root)
        buf = io.StringIO()
        tree.write(buf, encoding="unicode", xml_declaration=True)
        filename = self._make_filename("xml")
        self.export.file.save(filename, io.BytesIO(buf.getvalue().encode("utf-8")), save=False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_vulnerabilities(self) -> list[Vulnerability]:
        """Return filtered and sorted vulnerabilities per export options."""
        qs = Vulnerability.objects.filter(subproject=self.subproject)

        # Filter by status
        status_filter = self.options.get("vuln_status")
        if status_filter:
            qs = qs.filter(vuln_status__in=status_filter)

        # Filter by severity
        severity_filter = self.options.get("risk_levels")
        if severity_filter:
            qs = qs.filter(risk_level__in=severity_filter)

        return list(qs.order_by("-risk_score", "-cvss_score", "title"))

    def _render_html_template(self) -> str:
        """Render the Jinja2 template with full context."""
        vulnerabilities = self._get_vulnerabilities()
        severity_counts = dict(Counter(v.risk_level for v in vulnerabilities))

        # Generate charts
        charts = {
            "pie": severity_pie_chart(vulnerabilities),
            "bar": host_bar_chart(vulnerabilities),
            "risk_matrix": risk_matrix_chart(vulnerabilities),
            "timeline": "",
        }

        # Timeline chart (only if project has multiple subprojects)
        from apps.projects.models import SubProject
        if SubProject.objects.filter(project=self.project).count() > 1:
            timeline_data = build_timeline(self.project.pk)
            charts["timeline"] = timeline_chart(timeline_data)

        template_name = self.project.template_name or "default"
        template_file = "base.html"  # Could be extended to support multiple templates

        context = {
            "project": self.project,
            "subproject": self.subproject,
            "org": self.org,
            "vulnerabilities": vulnerabilities,
            "severity_counts": severity_counts,
            "charts": charts,
        }

        from jinja2 import FileSystemLoader
        from .jinja2_env import environment as setup_env
        template_dir = Path(settings.BASE_DIR) / "templates" / "reports"
        env = setup_env(loader=FileSystemLoader(str(template_dir)), autoescape=True)

        template = env.get_template(template_file)
        return template.render(**context)

    def _make_filename(self, ext: str) -> str:
        import re
        safe_title = re.sub(r"[^a-zA-Z0-9_-]", "_", self.project.title)[:40]
        return f"{self.export.pk}_{safe_title}.{ext}"
