"""
Views for the projects app.
Provides CRUD for Projects, SubProjects, Screenshots, and the lock mechanism.
"""

from __future__ import annotations

from django.db.models import Count, QuerySet
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import AuditLog
from apps.licensing.permissions import HasActiveLicense

from .models import Project, ProjectLock, Screenshot, SubProject
from .permissions import IsProjectLockHolder, IsProjectMember
from .serializers import (
    ProjectDetailSerializer,
    ProjectListSerializer,
    ScreenshotSerializer,
    SubProjectSerializer,
    SubProjectWriteSerializer,
)


def _get_user_ip(request: Request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR")


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


class ProjectListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/v1/projects/         → list organization's projects
    POST /api/v1/projects/         → create a new project (requires active license)
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == "POST":
            return ProjectDetailSerializer
        return ProjectListSerializer

    def get_queryset(self) -> QuerySet:
        return (
            Project.objects.filter(organization=self.request.user.organization)
            .annotate(subproject_count=Count("subprojects"))
            .select_related("lock", "lock__locked_by")
            .order_by("-created_at")
        )

    def create(self, request: Request, *args, **kwargs) -> Response:
        # License check for project creation
        license_perm = HasActiveLicense()
        if not license_perm.has_permission(request, self):
            return Response(
                {"detail": license_perm.message},
                status=status.HTTP_403_FORBIDDEN,
            )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        project = serializer.save(
            organization=request.user.organization,
            created_by=request.user,
        )
        AuditLog.log(
            action=AuditLog.Action.PROJECT_CREATED,
            user=request.user,
            detail={"project_id": project.pk, "title": project.title},
            ip_address=_get_user_ip(request),
        )
        return Response(
            ProjectDetailSerializer(project).data,
            status=status.HTTP_201_CREATED,
        )


class ProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/v1/projects/<pk>/  → project detail
    PATCH  /api/v1/projects/<pk>/  → update (lock required)
    DELETE /api/v1/projects/<pk>/  → delete (admin only)
    """

    serializer_class = ProjectDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsProjectMember]

    def get_queryset(self) -> QuerySet:
        return Project.objects.filter(
            organization=self.request.user.organization
        ).select_related("lock", "lock__locked_by", "created_by").prefetch_related("subprojects")

    def get_object(self) -> Project:
        obj = get_object_or_404(self.get_queryset(), pk=self.kwargs["pk"])
        self.check_object_permissions(self.request, obj)
        return obj

    def update(self, request: Request, *args, **kwargs) -> Response:
        project = self.get_object()
        lock_perm = IsProjectLockHolder()
        if not lock_perm.has_object_permission(request, self, project):
            return Response(
                {"detail": lock_perm.message},
                status=status.HTTP_423_LOCKED,
            )
        return super().update(request, *args, partial=True, **kwargs)

    def destroy(self, request: Request, *args, **kwargs) -> Response:
        if not request.user.is_org_admin:
            return Response(
                {"detail": "Only organization admins can delete projects."},
                status=status.HTTP_403_FORBIDDEN,
            )
        return super().destroy(request, *args, **kwargs)


# ---------------------------------------------------------------------------
# SubProjects
# ---------------------------------------------------------------------------


class SubProjectListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/v1/projects/<project_pk>/subprojects/
    POST /api/v1/projects/<project_pk>/subprojects/
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == "POST":
            return SubProjectWriteSerializer
        return SubProjectSerializer

    def _get_project(self) -> Project:
        project = get_object_or_404(
            Project,
            pk=self.kwargs["project_pk"],
            organization=self.request.user.organization,
        )
        return project

    def get_queryset(self) -> QuerySet:
        return (
            SubProject.objects.filter(project=self._get_project())
            .annotate(vulnerability_count=Count("vulnerabilities"))
            .order_by("scan_date", "created_at")
        )

    def create(self, request: Request, *args, **kwargs) -> Response:
        project = self._get_project()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        subproject = serializer.save(project=project, created_by=request.user)
        return Response(
            SubProjectSerializer(subproject).data,
            status=status.HTTP_201_CREATED,
        )


class SubProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/v1/projects/<project_pk>/subprojects/<pk>/
    PATCH  /api/v1/projects/<project_pk>/subprojects/<pk>/
    DELETE /api/v1/projects/<project_pk>/subprojects/<pk>/
    """

    serializer_class = SubProjectWriteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self) -> QuerySet:
        return SubProject.objects.filter(
            project__organization=self.request.user.organization,
            project_id=self.kwargs["project_pk"],
        )

    def retrieve(self, request: Request, *args, **kwargs) -> Response:
        instance = self.get_object()
        return Response(SubProjectSerializer(instance).data)

    def update(self, request: Request, *args, **kwargs) -> Response:
        return super().update(request, *args, partial=True, **kwargs)


# ---------------------------------------------------------------------------
# Screenshots
# ---------------------------------------------------------------------------


class ScreenshotListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/v1/projects/<project_pk>/subprojects/<subproject_pk>/screenshots/
    POST /api/v1/projects/<project_pk>/subprojects/<subproject_pk>/screenshots/
    """

    serializer_class = ScreenshotSerializer
    permission_classes = [permissions.IsAuthenticated]

    def _get_subproject(self) -> SubProject:
        return get_object_or_404(
            SubProject,
            pk=self.kwargs["subproject_pk"],
            project__pk=self.kwargs["project_pk"],
            project__organization=self.request.user.organization,
        )

    def get_queryset(self) -> QuerySet:
        return Screenshot.objects.filter(subproject=self._get_subproject())

    def perform_create(self, serializer: ScreenshotSerializer) -> None:  # type: ignore[override]
        serializer.save(
            subproject=self._get_subproject(),
            uploaded_by=self.request.user,
        )


class ScreenshotDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/v1/screenshots/<pk>/
    PATCH  /api/v1/screenshots/<pk>/
    DELETE /api/v1/screenshots/<pk>/
    """

    serializer_class = ScreenshotSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self) -> QuerySet:
        return Screenshot.objects.filter(
            subproject__project__organization=self.request.user.organization
        )

    def update(self, request: Request, *args, **kwargs) -> Response:
        return super().update(request, *args, partial=True, **kwargs)


# ---------------------------------------------------------------------------
# Project Lock
# ---------------------------------------------------------------------------


class ProjectLockAcquireView(APIView):
    """
    POST /api/v1/projects/<pk>/lock/acquire/
    Acquires the lock for the authenticated user. Returns 423 if held by someone else.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, pk: int) -> Response:
        project = get_object_or_404(
            Project,
            pk=pk,
            organization=request.user.organization,
        )

        try:
            lock = project.lock
            if not lock.is_expired() and lock.locked_by_id != request.user.pk:
                return Response(
                    {
                        "detail": f"Project is locked by {lock.locked_by.full_name} since {lock.locked_at:%H:%M}.",
                        "locked_by": lock.locked_by.full_name,
                        "locked_at": lock.locked_at,
                    },
                    status=status.HTTP_423_LOCKED,
                )
            # Expired or same user — take over
            lock.locked_by = request.user
            lock.locked_at = timezone.now()
            lock.last_heartbeat = timezone.now()
            lock.save()
        except Project.lock.RelatedObjectDoesNotExist:
            lock = ProjectLock.objects.create(project=project, locked_by=request.user)

        return Response({"detail": "Lock acquired.", "locked_at": lock.locked_at})


class ProjectLockHeartbeatView(APIView):
    """
    POST /api/v1/projects/<pk>/lock/heartbeat/
    Refreshes the lock heartbeat to prevent expiry (called every 60s by frontend).
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, pk: int) -> Response:
        project = get_object_or_404(
            Project,
            pk=pk,
            organization=request.user.organization,
        )

        try:
            lock = project.lock
            if lock.locked_by_id != request.user.pk:
                return Response(
                    {"detail": "You do not hold this lock."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            lock.refresh()
            return Response({"detail": "Heartbeat received.", "last_heartbeat": lock.last_heartbeat})
        except Project.lock.RelatedObjectDoesNotExist:
            return Response(
                {"detail": "No lock to refresh."},
                status=status.HTTP_404_NOT_FOUND,
            )


class ProjectLockReleaseView(APIView):
    """
    POST /api/v1/projects/<pk>/lock/release/
    Releases the lock held by the authenticated user.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request, pk: int) -> Response:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer

        project = get_object_or_404(
            Project,
            pk=pk,
            organization=request.user.organization,
        )

        try:
            lock = project.lock
            if lock.locked_by_id != request.user.pk and not lock.is_expired():
                return Response(
                    {"detail": "You do not hold this lock."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            lock.delete()
        except Project.lock.RelatedObjectDoesNotExist:
            pass  # Already released — idempotent

        # Notify other clients via WebSocket
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"project_lock_{pk}",
            {
                "type": "lock.released",
                "released_by": request.user.full_name,
                "project_id": pk,
            },
        )

        return Response({"detail": "Lock released."})
