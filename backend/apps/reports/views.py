"""
Views for the reports app.
"""

from __future__ import annotations


from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework import permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import AuditLog
from apps.licensing.permissions import HasActiveLicense
from apps.projects.models import SubProject

from .models import ReportExport
from .serializers import ReportExportSerializer, ReportGenerateSerializer


def _get_user_ip(request: Request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")


class ReportGenerateView(APIView):
    """
    POST /api/v1/reports/generate/
    Queue a report generation job. Returns a ReportExport record immediately.
    Actual generation runs via Celery.
    Requires active license.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        # License check
        if not HasActiveLicense().has_permission(request, self):
            return Response(
                {"detail": "Active license required to export reports."},
                status=status.HTTP_403_FORBIDDEN,
            )

        serializer = ReportGenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # IDOR: verify subproject ownership
        subproject = get_object_or_404(
            SubProject,
            pk=data["subproject"],
            project__organization=request.user.organization,
        )

        # Merge statuses from both field names; frontend sends "statuses".
        vuln_status = data.get("statuses") or data.get("vuln_status") or []

        options: dict = {}
        if vuln_status:
            options["vuln_status"] = vuln_status
        if data.get("risk_levels"):
            options["risk_levels"] = data["risk_levels"]
        if data.get("report_type"):
            options["report_type"] = data["report_type"]
        if data.get("sections"):
            options["sections"] = data["sections"]
        if data.get("audience"):
            options["audience"] = data["audience"]
        if data.get("style"):
            options["style"] = data["style"]
        if data.get("extra"):
            options["extra"] = data["extra"]
        if data.get("charts_enabled"):
            options["charts_enabled"] = data["charts_enabled"]
        if data.get("charts_variants"):
            options["charts_variants"] = data["charts_variants"]
        if data.get("charts_details"):
            options["charts_details"] = data["charts_details"]
        if data.get("scan_import_ids"):
            options["scan_import_ids"] = data["scan_import_ids"]
        if data.get("section_overrides"):
            # Sanitise: keep only entries whose value is a dict with a non-empty
            # 'custom_text' string, so the template never receives malformed data.
            options["section_overrides"] = {
                k: {"custom_text": str(v.get("custom_text", ""))}
                for k, v in data["section_overrides"].items()
                if isinstance(v, dict) and v.get("custom_text")
            }

        from .generator import REPORT_TYPE_LABELS
        report_type_val = data.get("report_type", "")
        type_label = REPORT_TYPE_LABELS.get(report_type_val, "Security Assessment Report")
        fmt_upper = data["format"].upper()
        report_name = f"{type_label} · {fmt_upper}"

        export = ReportExport.objects.create(
            subproject=subproject,
            format=data["format"],
            options=options,
            report_name=report_name,
            generated_by=request.user,
        )

        # Trigger async generation
        from .tasks import generate_report
        generate_report.delay(export.pk)

        AuditLog.log(
            action=AuditLog.Action.PROJECT_EXPORTED,
            user=request.user,
            detail={
                "export_id": export.pk,
                "format": data["format"],
                "subproject_id": subproject.pk,
            },
            ip_address=_get_user_ip(request),
        )

        return Response(
            ReportExportSerializer(export, context={"request": request}).data,
            status=status.HTTP_201_CREATED,
        )


class ReportExportDetailView(APIView):
    """
    GET /api/v1/reports/exports/<pk>/
    Check generation status and get download link.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request, pk: int) -> Response:
        export = get_object_or_404(
            ReportExport,
            pk=pk,
            subproject__project__organization=request.user.organization,
        )
        return Response(
            ReportExportSerializer(export, context={"request": request}).data
        )


class ReportExportDownloadView(APIView):
    """
    GET /api/v1/reports/exports/<pk>/download/
    Stream the generated report file.
    Requires active license.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request, pk: int) -> FileResponse | Response:
        if not HasActiveLicense().has_permission(request, self):
            return Response(
                {"detail": "Active license required to download reports."},
                status=status.HTTP_403_FORBIDDEN,
            )

        export = get_object_or_404(
            ReportExport,
            pk=pk,
            subproject__project__organization=request.user.organization,
            status=ReportExport.Status.DONE,
        )

        if not export.file:
            return Response({"detail": "File not available."}, status=status.HTTP_404_NOT_FOUND)

        content_types = {
            ReportExport.Format.PDF: "application/pdf",
            ReportExport.Format.HTML: "text/html",
            ReportExport.Format.XML: "application/xml",
        }

        return FileResponse(
            export.file.open("rb"),
            content_type=content_types.get(export.format, "application/octet-stream"),
            as_attachment=True,
            filename=export.file.name.split("/")[-1],
        )


class ReportExportListView(APIView):
    """
    GET /api/v1/reports/exports/?subproject=<pk>
    List all exports for a subproject.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        subproject_id = request.query_params.get("subproject")
        qs = ReportExport.objects.filter(
            subproject__project__organization=request.user.organization
        )
        if subproject_id:
            qs = qs.filter(subproject_id=subproject_id)
        return Response(
            ReportExportSerializer(qs, many=True, context={"request": request}).data
        )


class ReportPresetsView(APIView):
    """
    GET /api/v1/reports/presets/?report_type=<type>&audience=<audience>

    Returns recommended sections, chart defaults, and tool guidance for a
    given report_type × audience combination.  Used by the frontend Report
    Builder to pre-populate sensible defaults when the user picks a type.
    """

    permission_classes = [permissions.IsAuthenticated]

    # Sections recommended per report_type × audience.
    # Falls back to _AUDIENCE_DEFAULTS when a type-specific override is absent.
    _AUDIENCE_DEFAULTS: dict[str, list[str]] = {
        "executive": [
            "toc", "executive_summary", "recommendations", "appendix",
        ],
        "management": [
            "toc", "doc_control", "executive_summary", "findings_summary",
            "remediation_plan", "risk_register", "recommendations",
        ],
        "technical": [
            "toc", "doc_control", "scope", "engagement_overview",
            "vuln_details", "host_breakdown", "remediation_plan",
            "mitre_mapping", "appendix",
        ],
    }

    _TYPE_SECTIONS: dict[str, dict[str, list[str]]] = {
        "pentest": {
            "executive": ["toc", "executive_summary", "recommendations"],
            "management": [
                "toc", "doc_control", "executive_summary", "findings_summary",
                "remediation_plan", "risk_register", "recommendations",
            ],
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "vuln_details", "host_breakdown", "attack_paths",
                "attack_narrative", "remediation_plan", "appendix",
            ],
        },
        "va": {
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "vuln_details", "host_breakdown", "remediation_plan",
                "risk_register", "appendix",
            ],
        },
        "web_app": {
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "owasp_coverage", "vuln_details", "host_breakdown",
                "remediation_plan", "appendix",
            ],
        },
        "mobile_app": {
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "masvs_coverage", "vuln_details", "remediation_plan", "appendix",
            ],
        },
        "red_team": {
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "attack_timeline", "attack_narrative", "attack_paths",
                "ioc", "vuln_details", "remediation_plan", "mitre_mapping", "appendix",
            ],
        },
        "cloud": {
            "technical": [
                "toc", "doc_control", "scope", "cloud_posture_overview",
                "vuln_details", "host_breakdown", "remediation_plan",
                "compliance_matrix", "appendix",
            ],
        },
        "network": {
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "network_overview", "vuln_details", "host_breakdown",
                "remediation_plan", "appendix",
            ],
        },
        "code_review": {
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "vuln_details", "owasp_coverage", "remediation_plan", "appendix",
            ],
        },
        "osint": {
            "technical": [
                "toc", "doc_control", "scope", "passive_recon", "web_surface",
                "content_discovery", "digital_footprint", "credential_exposure",
                "osint_findings", "recommendations", "appendix",
            ],
        },
        "compliance": {
            "management": [
                "toc", "doc_control", "scope", "compliance_matrix",
                "risk_register", "remediation_plan", "recommendations",
            ],
            "technical": [
                "toc", "doc_control", "scope", "engagement_overview",
                "compliance_matrix", "owasp_coverage", "vuln_details",
                "remediation_plan", "appendix",
            ],
        },
        "incident": {
            "technical": [
                "toc", "doc_control", "scope", "attack_timeline",
                "ioc", "vuln_details", "remediation_plan", "appendix",
            ],
        },
        "forensic": {
            "technical": [
                "toc", "doc_control", "scope", "attack_timeline",
                "ioc", "credential_exposure", "digital_footprint", "appendix",
            ],
        },
        "attack_surface": {
            "technical": [
                "toc", "doc_control", "scope", "passive_recon", "web_surface",
                "network_overview", "vuln_details", "host_breakdown",
                "remediation_plan", "appendix",
            ],
        },
        "patch_mgmt": {
            "management": [
                "toc", "doc_control", "findings_summary", "remediation_plan",
                "risk_register", "recommendations",
            ],
        },
        "retest": {
            "technical": [
                "toc", "doc_control", "scope", "diff_retest",
                "vuln_details", "remediation_plan", "appendix",
            ],
        },
    }

    # Chart defaults per audience (technical gets everything; less as audience rises)
    _AUDIENCE_CHARTS: dict[str, dict[str, bool]] = {
        "executive": {
            "severity_donut": True,
            "risk_gauge": True,
        },
        "management": {
            "severity_donut": True,
            "risk_gauge": True,
            "top_hosts_bar": True,
            "remediation_effort": True,
            "fixed_vs_open": True,
        },
        "technical": {
            "severity_donut": True,
            "risk_gauge": True,
            "top_hosts_bar": True,
            "risk_matrix": True,
            "vuln_by_category": True,
            "remediation_effort": True,
            "fixed_vs_open": True,
            "cvss_radar": True,
            "epss_distribution": True,
            "vuln_by_host": True,
            "trend_line": True,
        },
    }

    def get(self, request: Request) -> Response:
        from .generator import REPORT_TYPE_LABELS, REPORT_TYPE_TOOLS
        from apps.vulnerabilities.models import ScanImport

        report_type = request.query_params.get("report_type", "")
        audience = request.query_params.get("audience", "technical")
        if audience not in self._AUDIENCE_DEFAULTS:
            audience = "technical"

        # Sections
        type_overrides = self._TYPE_SECTIONS.get(report_type, {})
        sections = (
            type_overrides.get(audience)
            or self._AUDIENCE_DEFAULTS.get(audience, self._AUDIENCE_DEFAULTS["technical"])
        )

        # Charts
        charts_enabled = self._AUDIENCE_CHARTS.get(audience, self._AUDIENCE_CHARTS["technical"])

        # Tools
        tool_config = REPORT_TYPE_TOOLS.get(report_type, {})
        tool_label_map = dict(ScanImport.Tool.choices)

        def _labeled(ids: list[str]) -> list[dict]:
            return [{"id": t, "label": tool_label_map.get(t, t)} for t in ids]

        return Response({
            "report_type":       report_type,
            "report_type_label": REPORT_TYPE_LABELS.get(report_type, "Security Assessment Report"),
            "audience":          audience,
            "sections":          sections,
            "charts_enabled":    charts_enabled,
            "tools": {
                "required":    _labeled(tool_config.get("required", [])),
                "recommended": _labeled(tool_config.get("recommended", [])),
                "optional":    _labeled(tool_config.get("optional", [])),
            },
        })
