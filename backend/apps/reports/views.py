"""
Views for the reports app.
"""

from __future__ import annotations

import http

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
