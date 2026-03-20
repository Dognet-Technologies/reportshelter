"""
Views for the vulnerabilities app.
Provides CRUD for Vulnerabilities, ScanImport upload, diff, and timeline endpoints.
"""

from __future__ import annotations

import os

from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, generics, permissions, status
from rest_framework.parsers import MultiPartParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import AuditLog
from apps.licensing.permissions import HasActiveLicense
from apps.projects.models import SubProject

from .deduplication import build_timeline, compute_diff
from .models import ScanImport, Vulnerability
from .serializers import (
    ScanImportSerializer,
    ScanImportUploadSerializer,
    VulnerabilityListSerializer,
    VulnerabilitySerializer,
)


def _get_user_ip(request: Request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")


class VulnerabilityListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/v1/vulnerabilities/?subproject=<id>  → list vulnerabilities
    POST /api/v1/vulnerabilities/                   → create manually
    """

    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ["risk_level", "vuln_status", "subproject", "is_recurring"]
    search_fields = ["title", "description", "affected_host", "cve_id"]
    ordering_fields = ["risk_score", "cvss_score", "risk_level", "created_at"]
    ordering = ["-risk_score"]

    def get_serializer_class(self):
        if self.request.method == "POST":
            return VulnerabilitySerializer
        return VulnerabilityListSerializer

    def get_queryset(self):
        return Vulnerability.objects.filter(
            subproject__project__organization=self.request.user.organization
        )

    def create(self, request: Request, *args, **kwargs) -> Response:
        subproject_id = request.data.get("subproject")
        # Verify ownership
        get_object_or_404(
            SubProject,
            pk=subproject_id,
            project__organization=request.user.organization,
        )
        return super().create(request, *args, **kwargs)


class VulnerabilityDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/v1/vulnerabilities/<pk>/
    PATCH  /api/v1/vulnerabilities/<pk>/
    DELETE /api/v1/vulnerabilities/<pk>/
    """

    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Vulnerability.objects.filter(
            subproject__project__organization=self.request.user.organization
        )

class ScanImportUploadView(APIView):
    """
    POST /api/v1/vulnerabilities/import/<subproject_pk>/
    Upload a scanner file; triggers async Celery parsing.
    Requires active license.
    """

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser]

    def post(self, request: Request, subproject_pk: int) -> Response:
        # License check
        if not HasActiveLicense().has_permission(request, self):
            return Response({"detail": "Active license required to import scans."}, status=status.HTTP_403_FORBIDDEN)

        subproject = get_object_or_404(
            SubProject,
            pk=subproject_pk,
            project__organization=request.user.organization,
        )

        serializer = ScanImportUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["file"]
        tool = serializer.validated_data["tool"]

        # Security: validate extension
        from django.conf import settings

        ext = os.path.splitext(uploaded_file.name)[1].lower()
        allowed_exts = getattr(settings, "ALLOWED_UPLOAD_EXTENSIONS", [".xml", ".json", ".csv", ".nmap", ".txt"])
        if ext not in allowed_exts:
            return Response(
                {"detail": f"File extension '{ext}' not allowed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Security: validate MIME type
        import magic

        mime = magic.from_buffer(uploaded_file.read(2048), mime=True)
        uploaded_file.seek(0)
        allowed_mimes = getattr(settings, "ALLOWED_UPLOAD_MIME_TYPES", [])
        if mime not in allowed_mimes:
            return Response(
                {"detail": f"File MIME type '{mime}' not allowed."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan_import = ScanImport.objects.create(
            subproject=subproject,
            tool=tool,
            file=uploaded_file,
            original_filename=uploaded_file.name,
            imported_by=request.user,
        )

        # Trigger async Celery task
        from apps.parsers.tasks import parse_scan_file

        parse_scan_file.delay(scan_import.pk)

        AuditLog.log(
            action=AuditLog.Action.FILE_IMPORTED,
            user=request.user,
            detail={
                "scan_import_id": scan_import.pk,
                "tool": tool,
                "filename": uploaded_file.name,
            },
            ip_address=_get_user_ip(request),
        )

        return Response(ScanImportSerializer(scan_import).data, status=status.HTTP_201_CREATED)


class ScanImportListView(generics.ListAPIView):
    """
    GET /api/v1/vulnerabilities/imports/?subproject=<pk>
    List all scan imports for a subproject (plain array, no pagination).
    """

    serializer_class = ScanImportSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = None  # Return plain list, not paginated object

    def get_queryset(self):
        qs = ScanImport.objects.filter(
            subproject__project__organization=self.request.user.organization
        ).order_by("-imported_at")
        subproject_pk = self.request.query_params.get("subproject")
        if subproject_pk:
            qs = qs.filter(subproject_id=subproject_pk)
        return qs


class ScanImportDetailView(generics.RetrieveAPIView):
    """
    GET /api/v1/vulnerabilities/imports/<pk>/
    Check the status of a scan import.
    """

    serializer_class = ScanImportSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return ScanImport.objects.filter(
            subproject__project__organization=self.request.user.organization
        )


class ScanImportCancelView(APIView):
    """
    POST /api/v1/vulnerabilities/imports/<pk>/cancel/
    Cancel a pending or processing scan import.
    Marks the record as failed and revokes the Celery task if possible.
    Idempotent: cancelling an already-failed import returns 200.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, pk: int) -> Response:
        # Use only() to avoid selecting celery_task_id via SELECT *
        # in case the migration has not been applied yet.
        try:
            scan_import = get_object_or_404(
                ScanImport,
                pk=pk,
                subproject__project__organization=request.user.organization,
            )
        except Exception as exc:
            logger.error("ScanImportCancelView: DB error fetching import %s: %s", pk, exc)
            return Response({"detail": "Database error — run migrations."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if scan_import.status == ScanImport.Status.DONE:
            return Response(
                {"detail": "Import already completed — cannot cancel."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Already failed → idempotent, just return current state
        if scan_import.status == ScanImport.Status.FAILED:
            return Response(ScanImportSerializer(scan_import).data)

        # Mark as failed immediately so the task won't call mark_done
        scan_import.mark_failed("Cancelled by user.")

        # Revoke the Celery task if we have its ID (field may not exist on old records)
        task_id = getattr(scan_import, "celery_task_id", "") or ""
        if task_id:
            try:
                from config.celery import app as celery_app
                celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
                logger.info("Revoked Celery task %s for ScanImport %s.", task_id, pk)
            except Exception as exc:
                logger.warning("Could not revoke Celery task: %s", exc)

        return Response(ScanImportSerializer(scan_import).data)


class ScanImportRetryView(APIView):
    """
    POST /api/v1/vulnerabilities/imports/<pk>/retry/
    Re-queue a scan import that is stuck in 'processing' or has 'failed'.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, pk: int) -> Response:
        scan_import = get_object_or_404(
            ScanImport,
            pk=pk,
            subproject__project__organization=request.user.organization,
        )

        if scan_import.status == ScanImport.Status.DONE:
            return Response(
                {"detail": "Import already completed successfully."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Reset to pending so the UI shows the right state before the task runs
        scan_import.status = ScanImport.Status.PENDING
        scan_import.error_message = ""
        scan_import.save(update_fields=["status", "error_message"])

        from apps.parsers.tasks import parse_scan_file
        parse_scan_file.delay(scan_import.pk)

        logger.info("ScanImport %s re-queued by %s.", pk, request.user.email)
        return Response(ScanImportSerializer(scan_import).data)


class VulnerabilityDiffView(APIView):
    """
    GET /api/v1/vulnerabilities/diff/?current=<sp_id>&previous=<sp_id>
    Compute diff between two SubProjects.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        current_id = request.query_params.get("current")
        previous_id = request.query_params.get("previous")

        if not current_id or not previous_id:
            return Response(
                {"detail": "'current' and 'previous' query params required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # IDOR: verify both subprojects belong to the user's org
        get_object_or_404(SubProject, pk=current_id, project__organization=request.user.organization)
        get_object_or_404(SubProject, pk=previous_id, project__organization=request.user.organization)

        diff = compute_diff(int(current_id), int(previous_id))

        return Response({
            "new": VulnerabilityListSerializer(diff.new, many=True).data,
            "fixed": VulnerabilityListSerializer(diff.fixed, many=True).data,
            "persistent": VulnerabilityListSerializer(diff.persistent, many=True).data,
            "changed": VulnerabilityListSerializer(diff.changed, many=True).data,
        })


class ProjectTimelineView(APIView):
    """
    GET /api/v1/vulnerabilities/timeline/<project_pk>/
    Returns chronological timeline of SubProject metrics.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request, project_pk: int) -> Response:
        from apps.projects.models import Project

        get_object_or_404(Project, pk=project_pk, organization=request.user.organization)
        timeline = build_timeline(project_pk)
        return Response(timeline)
