"""
Report generation logic.
Assembles context, renders Jinja2 template, and produces PDF/HTML/XML output.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

from django.conf import settings
from django.db import models

from apps.vulnerabilities.deduplication import build_timeline
from apps.vulnerabilities.models import RISK_LEVEL_ORDER, ScanImport, Vulnerability

from .charts import (
    cvss_breakdown_chart,
    epss_distribution_chart,
    fixed_vs_open_chart,
    host_bar_chart,
    remediation_effort_chart,
    risk_gauge_chart,
    risk_matrix_chart,
    severity_pie_chart,
    timeline_chart,
    vulns_by_category_chart,
    vulns_per_host_chart,
)
from .models import ReportExport

# Human-readable labels for report type IDs (matches frontend reportTypes.ts).
REPORT_TYPE_LABELS: dict[str, str] = {
    "pentest":        "Penetration Test Report",
    "va":             "Vulnerability Assessment",
    "red_team":       "Red Team Report",
    "web_app":        "Web Application Security Report",
    "mobile_app":     "Mobile Application Security Report",
    "cloud":          "Cloud Security Assessment",
    "network":        "Network Security Assessment",
    "social_eng":     "Social Engineering Report",
    "incident":       "Incident Response Report",
    "threat_intel":   "Threat Intelligence Report",
    "compliance":     "Compliance Gap Assessment",
    "osint":          "OSINT Report",
    "executive":      "Executive Summary",
    "it_infra":       "IT Infrastructure Assessment",
    "code_review":    "Code Review Report",
    "arch_review":    "Architecture Review",
    "dr":             "Disaster Recovery Assessment",
    "it_audit":       "IT Audit",
    "remediation":    "Remediation Plan",
    "retest":         "Retest / Verification Report",
    "risk_register":  "Risk Register",
    "patch_mgmt":     "Patch Management Report",
    "breach":         "Breach Notification Report",
    "forensic":       "Forensic Investigation Report",
    "malware":        "Malware Analysis Report",
    "lessons_learned":"Post-Incident Lessons Learned",
    "attack_surface": "Attack Surface Assessment",
}

# All known section IDs — used as fallback when sections list is empty.
ALL_SECTIONS: set[str] = {
    # Structural (always rendered, never counted for fallback)
    "cover", "last_page",
    # Universal
    "toc", "doc_control",
    # Main content sections (frontend section IDs)
    "executive_summary", "findings_summary", "risk_summary",
    "scope", "engagement_overview",
    "attack_timeline", "attack_narrative", "attack_paths",
    "ioc", "vuln_details", "host_breakdown",
    "remediation_plan", "diff_retest", "risk_register", "compliance_matrix",
    "osint_findings", "digital_footprint", "credential_exposure",
    "owasp_coverage", "masvs_coverage", "mitre_mapping", "detection_gap",
    "cloud_posture_overview", "network_overview",
    "passive_recon", "web_surface", "content_discovery",
    "recommendations", "appendix",
}


# Sections always rendered in the template regardless of user selection.
# They must not be counted when deciding whether to fall back to ALL_SECTIONS.
_STRUCTURAL_SECTIONS = frozenset({"cover", "last_page"})


# ---------------------------------------------------------------------------
# Tool guidance — maps each report type to the tools that feed it.
# "required":    primary data sources; report is incomplete without them.
# "recommended": significantly improve coverage and chart quality.
# "optional":    supplementary; narrow scope or specialist use.
# Tool IDs match ScanImport.Tool choices.
# ---------------------------------------------------------------------------
REPORT_TYPE_TOOLS: dict[str, dict[str, list[str]]] = {
    "pentest": {
        "required":    ["nmap"],
        "recommended": ["burp", "zap", "nikto", "metasploit", "nessus"],
        "optional":    ["hydra", "wfuzz", "nuclei", "gitleaks", "sslscan", "ssh_audit", "openvas"],
    },
    "va": {
        "required":    ["nessus", "openvas", "nexpose", "qualys"],
        "recommended": ["nmap", "nuclei"],
        "optional":    ["ssh_audit", "sslscan", "qualys_webapp"],
    },
    "red_team": {
        "required":    ["metasploit", "cobalt"],
        "recommended": ["nmap", "hydra", "gitleaks"],
        "optional":    ["pentest_pipeline", "wfuzz", "nuclei"],
    },
    "web_app": {
        "required":    ["burp", "zap", "acunetix", "netsparker"],
        "recommended": ["nikto", "wapiti", "nuclei", "qualys_webapp"],
        "optional":    ["wfuzz", "wpscan", "immuniweb", "arachni"],
    },
    "mobile_app": {
        "required":    [],
        "recommended": ["nuclei"],
        "optional":    ["csv"],
    },
    "cloud": {
        "required":    ["aws_inspector2", "awssecurityhub", "cloudsploit"],
        "recommended": ["trivy", "nuclei"],
        "optional":    ["nmap", "dockerbench"],
    },
    "network": {
        "required":    ["nmap"],
        "recommended": ["nessus", "nexpose", "qualys", "ssh_audit", "sslscan"],
        "optional":    ["openvas", "nuclei"],
    },
    "social_eng": {
        "required":    [],
        "recommended": ["csv"],
        "optional":    [],
    },
    "incident": {
        "required":    ["sysdig"],
        "recommended": ["gitleaks"],
        "optional":    ["csv"],
    },
    "threat_intel": {
        "required":    [],
        "recommended": ["pentest_pipeline", "csv"],
        "optional":    ["cycognito"],
    },
    "compliance": {
        "required":    ["nessus", "qualys", "awssecurityhub", "dockerbench"],
        "recommended": ["redhatsatellite", "nuclei"],
        "optional":    ["nmap", "openvas"],
    },
    "osint": {
        "required":    ["pentest_pipeline", "cycognito"],
        "recommended": ["nuclei", "nmap"],
        "optional":    [],
    },
    "executive": {
        "required":    [],
        "recommended": [],
        "optional":    [],
    },
    "it_infra": {
        "required":    ["nmap"],
        "recommended": ["nessus", "nexpose", "ssh_audit", "sslscan"],
        "optional":    ["redhatsatellite", "qualys"],
    },
    "code_review": {
        "required":    ["sonarqube", "codechecker", "github_vulnerability"],
        "recommended": ["gitleaks", "cargo_audit"],
        "optional":    ["gitlab_container_scan", "trivy"],
    },
    "arch_review": {
        "required":    [],
        "recommended": ["csv"],
        "optional":    [],
    },
    "dr": {
        "required":    [],
        "recommended": ["csv"],
        "optional":    [],
    },
    "it_audit": {
        "required":    ["nessus", "qualys", "dockerbench"],
        "recommended": ["redhatsatellite", "github_vulnerability"],
        "optional":    ["nmap"],
    },
    "remediation": {
        "required":    [],
        "recommended": [],
        "optional":    [],
    },
    "retest": {
        "required":    [],
        "recommended": [],
        "optional":    [],
    },
    "risk_register": {
        "required":    [],
        "recommended": [],
        "optional":    [],
    },
    "patch_mgmt": {
        "required":    ["nessus", "nexpose", "qualys", "redhatsatellite"],
        "recommended": ["github_vulnerability"],
        "optional":    ["nmap"],
    },
    "breach": {
        "required":    ["gitleaks", "hydra"],
        "recommended": ["sysdig"],
        "optional":    ["csv"],
    },
    "forensic": {
        "required":    ["sysdig"],
        "recommended": ["gitleaks"],
        "optional":    ["csv"],
    },
    "malware": {
        "required":    ["sysdig", "trivy"],
        "recommended": [],
        "optional":    ["csv"],
    },
    "lessons_learned": {
        "required":    [],
        "recommended": ["csv"],
        "optional":    [],
    },
    "attack_surface": {
        "required":    ["nmap", "cycognito"],
        "recommended": ["nuclei", "pentest_pipeline"],
        "optional":    ["sslscan", "ssh_audit", "nessus"],
    },
}


def _overall_risk(severity_counts: dict) -> tuple[str, str]:
    """Return (risk_label, hex_color) representing the worst finding severity."""
    for level, color in [
        ("critical", "#dc2626"),
        ("high",     "#ea580c"),
        ("medium",   "#d97706"),
        ("low",      "#2563eb"),
    ]:
        if severity_counts.get(level, 0) > 0:
            return level.upper(), color
    return "INFO", "#6b7280"


def _make_ci_fn(section_overrides: dict):
    """
    Return a _ci() callable for use as a Jinja2 context variable.
    Renders the user-authored custom intro block for a section (if any),
    returning safe Markup so Jinja2 does not double-escape the HTML.
    """
    from markupsafe import Markup

    def _nl2br(text: str) -> str:
        escaped = (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        return escaped.replace("\n", "<br/>\n")

    def _ci(sid: str) -> Markup:
        ov = section_overrides.get(sid, {})
        ct = ov.get("custom_text", "") if isinstance(ov, dict) else ""
        if ct:
            return Markup(f'<div class="section-custom-intro">{_nl2br(ct)}</div>')
        return Markup("")

    return _ci


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
            ET.SubElement(vuln_el, "affected_host").text = v.affected_host or ""
            ET.SubElement(vuln_el, "affected_port").text = str(v.affected_port) if v.affected_port is not None else ""
            ET.SubElement(vuln_el, "cve_id").text = ", ".join(v.cve_id) if v.cve_id else ""
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

        # Filter by scan import — only include vulns from selected imports.
        # Manually-created vulns (scan_import=None) are always included.
        scan_import_ids = self.options.get("scan_import_ids")
        if scan_import_ids:
            qs = qs.filter(
                models.Q(scan_import__isnull=True) | models.Q(scan_import_id__in=scan_import_ids)
            )

        from django.db.models import F

        return list(
            qs.annotate(risk_level_order=RISK_LEVEL_ORDER).order_by(
                F("risk_score").desc(nulls_last=True),
                F("cvss_score").desc(nulls_last=True),
                "risk_level_order",
                "title",
            )
        )

    def _get_enabled_sections(self) -> set[str]:
        """
        Return the set of content section IDs to render.

        "cover" and "last_page" are structural — they are always rendered in
        the template outside any conditional block, so they must not be counted
        when deciding whether the user actually selected content sections.

        Fall-back to ALL_SECTIONS when:
          - options contains no "sections" key, or
          - the list is empty, or
          - the list contains only structural sections (cover / last_page).
        """
        sections = self.options.get("sections") or []
        content = set(sections) - _STRUCTURAL_SECTIONS
        return content if content else ALL_SECTIONS

    def _get_tool_coverage(self) -> dict:
        """
        Return which tools have been imported for this subproject and how they compare
        to the recommended/required tool set for the chosen report type.
        """
        report_type = self.options.get("report_type", "")
        tool_config = REPORT_TYPE_TOOLS.get(report_type, {})
        tool_label_map = dict(ScanImport.Tool.choices)

        imports = list(
            ScanImport.objects.filter(
                subproject=self.subproject,
                status=ScanImport.Status.DONE,
            ).values("tool", "vulnerability_count")
        )

        tool_counts: dict[str, int] = {}
        for imp in imports:
            t = imp["tool"]
            tool_counts[t] = tool_counts.get(t, 0) + imp["vulnerability_count"]

        imported = [
            {
                "tool": t,
                "tool_label": tool_label_map.get(t, t.upper()),
                "vuln_count": count,
            }
            for t, count in sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        imported_ids = set(tool_counts.keys())
        required_ids = set(tool_config.get("required", []))
        recommended_ids = set(tool_config.get("recommended", []))

        required_missing = [tool_label_map.get(t, t) for t in (required_ids - imported_ids)]
        recommended_missing = [tool_label_map.get(t, t) for t in (recommended_ids - imported_ids)]

        return {
            "imported_tools":      imported,
            "required_missing":    sorted(required_missing),
            "recommended_missing": sorted(recommended_missing),
            "coverage_ok":         not required_missing,
        }

    def _build_hosts_breakdown(self, vulnerabilities: list[Vulnerability]) -> dict[str, list[Vulnerability]]:
        """Group vulnerabilities by affected_host, sorted by count desc."""
        grouped: dict[str, list[Vulnerability]] = defaultdict(list)
        for v in vulnerabilities:
            key = v.affected_host or "(unknown)"
            grouped[key].append(v)
        return dict(sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True))

    def _build_rpt_style(self) -> dict:
        """
        Build a flat style dict for the template, merging per-report overrides
        (options["style"]) with project-level defaults.
        """
        s    = self.options.get("style") or {}
        proj = self.project

        primary   = s.get("primaryColor")   or getattr(proj, "primary_color",   None) or "#3b82f6"
        secondary = s.get("secondaryColor") or getattr(proj, "secondary_color", None) or "#64748b"
        font      = s.get("font")           or getattr(proj, "font_family",     None) or "Inter"
        watermark = s.get("watermark")      or getattr(proj, "watermark_text",  None) or ""
        w_opacity = str(getattr(proj, "watermark_opacity", "0.15") or "0.15")

        br_map = {"none": "0px", "sm": "4px", "md": "10px", "lg": "20px"}
        br_px  = br_map.get(s.get("borderRadius", "md"), "10px")

        ts_map = {
            "sm": {"h1": "20pt", "h2": "13pt", "h3": "10pt"},
            "md": {"h1": "24pt", "h2": "16pt", "h3": "12pt"},
            "lg": {"h1": "28pt", "h2": "20pt", "h3": "14pt"},
            "xl": {"h1": "34pt", "h2": "24pt", "h3": "16pt"},
        }
        ts = ts_map.get(s.get("titleSize", "md"), ts_map["md"])

        return {
            "primary_color":    primary,
            "secondary_color":  secondary,
            "font":             font,
            "watermark":        watermark,
            "watermark_opacity": w_opacity,
            "border_radius_px": br_px,
            "evidence_style":   s.get("evidenceStyle", "box"),
            "title_h1":         ts["h1"],
            "title_h2":         ts["h2"],
            "title_h3":         ts["h3"],
        }

    def _build_rpt_extra(self) -> dict:
        """Return the per-report extra metadata dict."""
        e = self.options.get("extra") or {}
        return {
            "classification":  e.get("classification", "CONFIDENTIAL"),
            "version":         e.get("version", "1.0"),
            "scope":           e.get("scope", ""),
            "engagement_type": e.get("engagement_type", ""),
            "methodologies":   e.get("methodologies") or [],
            "authors":         e.get("authors", ""),
            "references":      e.get("references", ""),
        }

    def _build_charts(
        self,
        sections: set[str],
        vulnerabilities: list,
        audience: str = "technical",
    ) -> dict[str, str]:
        """
        Generate only the charts that are both enabled and relevant to active sections.
        All chart functions receive the audience parameter for rendering detail control.

        Chart ID mapping (frontend key → function):
          severity_donut      → severity_pie_chart
          risk_gauge          → risk_gauge_chart
          trend_line          → timeline_chart
          top_hosts_bar       → host_bar_chart
          risk_matrix         → risk_matrix_chart
          vuln_by_category    → vulns_by_category_chart
          remediation_effort  → remediation_effort_chart
          fixed_vs_open       → fixed_vs_open_chart
          cvss_radar          → cvss_breakdown_chart
          epss_distribution   → epss_distribution_chart
          vuln_by_host        → vulns_per_host_chart
        """
        enabled      = self.options.get("charts_enabled") or {}
        variants     = self.options.get("charts_variants") or {}
        use_defaults = not enabled

        def is_on(chart_id: str) -> bool:
            return enabled.get(chart_id, False) if not use_defaults else True

        def variant_of(chart_id: str, default: str = "") -> str:
            return variants.get(chart_id, default)

        charts: dict[str, str] = {
            "pie": "",
            "risk_gauge": "",
            "bar": "",
            "risk_matrix": "",
            "timeline": "",
            "vulns_by_category": "",
            "remediation_effort": "",
            "fixed_vs_open": "",
            "cvss_breakdown": "",
            "epss_distribution": "",
            "vulns_per_host": "",
        }

        summary_active = bool({"executive_summary", "risk_summary", "findings_summary"} & sections)
        vuln_active    = bool({"vuln_details", "host_breakdown", "risk_summary", "findings_summary"} & sections)

        # --- severity_donut ---
        if summary_active and is_on("severity_donut"):
            pie_variant = variant_of("severity_donut", "Donut")
            charts["pie"] = severity_pie_chart(
                vulnerabilities, variant=pie_variant, audience=audience
            )

        # --- risk_gauge ---
        if summary_active and is_on("risk_gauge"):
            charts["risk_gauge"] = risk_gauge_chart(vulnerabilities, audience=audience)

        # --- top5_hosts / host_bar ---
        # Frontend key: "top_hosts_bar"
        if (summary_active or vuln_active) and is_on("top_hosts_bar"):
            charts["bar"] = host_bar_chart(vulnerabilities, audience=audience)

        # --- risk_matrix ---
        if (summary_active or vuln_active) and is_on("risk_matrix"):
            charts["risk_matrix"] = risk_matrix_chart(vulnerabilities, audience=audience)

        # --- historical_trend / timeline ---
        # Frontend key: "trend_line"
        timeline_active = bool(
            {"appendix", "executive_summary", "risk_summary", "findings_summary"} & sections
        )
        if timeline_active and is_on("trend_line"):
            from apps.projects.models import SubProject
            if SubProject.objects.filter(project=self.project).count() > 1:
                charts["timeline"] = timeline_chart(
                    build_timeline(self.project.pk), audience=audience
                )

        # --- vulns_by_category ---
        # Frontend key: "vuln_by_category"
        if vuln_active and is_on("vuln_by_category"):
            charts["vulns_by_category"] = vulns_by_category_chart(
                vulnerabilities, audience=audience
            )

        # --- remediation_effort ---
        if (vuln_active or "remediation_plan" in sections) and is_on("remediation_effort"):
            charts["remediation_effort"] = remediation_effort_chart(
                vulnerabilities, audience=audience
            )

        # --- fixed_vs_open ---
        if (summary_active or "diff_retest" in sections) and is_on("fixed_vs_open"):
            charts["fixed_vs_open"] = fixed_vs_open_chart(
                vulnerabilities, audience=audience
            )

        # --- cvss_breakdown ---
        # Frontend key: "cvss_radar"
        if vuln_active and is_on("cvss_radar"):
            charts["cvss_breakdown"] = cvss_breakdown_chart(
                vulnerabilities, audience=audience
            )

        # --- epss_distribution ---
        if vuln_active and is_on("epss_distribution"):
            charts["epss_distribution"] = epss_distribution_chart(
                vulnerabilities, audience=audience
            )

        # --- vulns_per_host ---
        # Frontend key: "vuln_by_host"
        if (vuln_active or "host_breakdown" in sections) and is_on("vuln_by_host"):
            charts["vulns_per_host"] = vulns_per_host_chart(
                vulnerabilities, audience=audience
            )

        return charts

    def _render_html_template(self) -> str:
        """Render the Jinja2 template with full context."""
        vulnerabilities = self._get_vulnerabilities()
        severity_counts = dict(Counter(v.risk_level for v in vulnerabilities))
        sections        = self._get_enabled_sections()

        # Ordered list respects drag-and-drop user ordering.
        raw_ordered      = self.options.get("sections") or []
        _structural      = {"cover", "last_page"}
        ordered_sections: list[str] = [s for s in raw_ordered if s in sections and s not in _structural]
        # Safety net: append any enabled sections missing from the stored list.
        ordered_sections += [s for s in sections if s not in ordered_sections and s not in _structural]

        report_type       = self.options.get("report_type", "")
        report_type_label = REPORT_TYPE_LABELS.get(report_type, "Security Assessment Report")
        audience          = self.options.get("audience", "technical")

        rpt_style = self._build_rpt_style()
        rpt_extra = self._build_rpt_extra()
        charts    = self._build_charts(sections, vulnerabilities, audience=audience)
        hosts     = self._build_hosts_breakdown(vulnerabilities)

        section_overrides = self.options.get("section_overrides") or {}

        overall_risk_label, overall_risk_color = _overall_risk(severity_counts)
        immediate_action = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
        high_epss = sum(
            1 for v in vulnerabilities
            if v.epss_score is not None and v.epss_score >= 0.5
        )

        context = {
            "project":           self.project,
            "subproject":        self.subproject,
            "org":               self.org,
            "vulnerabilities":   vulnerabilities,
            "severity_counts":   severity_counts,
            "charts":            charts,
            # Section control
            "sections":          sections,           # set  — fast membership checks
            "ordered_sections":  ordered_sections,   # list — rendering order
            # Per-report style overrides (merged with project defaults)
            "rpt_style":         rpt_style,
            # Per-report extra metadata
            "rpt_extra":         rpt_extra,
            # Report metadata
            "report_type":       report_type,
            "report_type_label": report_type_label,
            "audience":          audience,
            # Pre-grouped data
            "hosts":             hosts,
            # Per-section custom intro text (kept for legacy access; _ci() is preferred)
            "section_overrides": section_overrides,
            # _ci() renders user-authored custom intro text for a section;
            # passed as a Python callable so all imported macros can use it
            # without needing their own Jinja2 imports.
            "_ci":               _make_ci_fn(section_overrides),
            # Tool coverage guidance shown on cover page (management/technical only)
            "tool_coverage":     self._get_tool_coverage(),
            # Pre-computed executive metrics (avoid complex Jinja2 calculations)
            "exec_metrics": {
                "overall_risk_label": overall_risk_label,
                "overall_risk_color": overall_risk_color,
                "immediate_action":   immediate_action,
                "high_epss":          high_epss,
            },
        }

        template_file = "base.html"
        template_dir = Path(settings.BASE_DIR) / "templates" / "reports"

        from jinja2 import FileSystemLoader
        from .jinja2_env import environment as setup_env
        env = setup_env(loader=FileSystemLoader(str(template_dir)), autoescape=True)

        template = env.get_template(template_file)
        return template.render(**context)

    def _make_filename(self, ext: str) -> str:
        import re
        safe_title = re.sub(r"[^a-zA-Z0-9_-]", "_", self.project.title)[:40]
        return f"{self.export.pk}_{safe_title}.{ext}"
