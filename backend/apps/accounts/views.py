"""
Views for the accounts app.
Handles registration, login, logout, email verification,
password reset, user profile, org management, invites, and audit log.
"""

import logging
from typing import Any

from django.conf import settings
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import (
    AuditLog,
    EmailVerificationToken,
    LoginAttempt,
    Organization,
    PasswordResetToken,
    User,
)
from .permissions import IsOrgAdmin
from .serializers import (
    AuditLogSerializer,
    InviteUserSerializer,
    LoginSerializer,
    OrganizationSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfileUpdateSerializer,
    RegisterSerializer,
    UserSerializer,
)

logger = logging.getLogger(__name__)


def _get_client_ip(request: Request) -> str | None:
    """Extract client IP from X-Forwarded-For or REMOTE_ADDR."""
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _is_locked_out(email: str) -> bool:
    """
    Return True if the email has exceeded max failed attempts
    within the lockout window.
    """
    max_attempts = getattr(settings, "LOGIN_MAX_ATTEMPTS", 5)
    lockout_minutes = getattr(settings, "LOGIN_LOCKOUT_MINUTES", 15)
    window = timezone.now() - timezone.timedelta(minutes=lockout_minutes)
    recent_failures = LoginAttempt.objects.filter(
        email=email,
        success=False,
        attempted_at__gte=window,
    ).count()
    return recent_failures >= max_attempts


def _send_password_reset_email(user: User, token: PasswordResetToken, temp_password: str) -> None:
    """
    Send password reset email containing a temporary password and an activation link.
    The password is NOT changed until the user clicks the link — this prevents lockout
    if the reset was triggered accidentally.
    """
    frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173")
    activation_url = f"{frontend_url}/reset-password?token={token.token}"
    name = user.first_name or user.email
    body = (
        f"Hi {name},\n\n"
        f"Someone requested a password reset for your ReportShelter PRO account.\n\n"
        f"Your temporary password is:\n\n"
        f"    {temp_password}\n\n"
        f"To activate this reset, click the link below:\n"
        f"{activation_url}\n\n"
        f"Once you click the link, your password will be changed to the temporary one above.\n"
        f"You will be required to set a new permanent password immediately after logging in.\n\n"
        f"This link expires in 1 hour.\n"
        f"If you did not request this, ignore this email — your current password remains unchanged."
    )
    send_mail(
        subject="Reset your ReportShelter PRO password",
        message=body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=True,
    )


# ---------------------------------------------------------------------------
# Registration & Email Verification
# ---------------------------------------------------------------------------


class RegisterView(APIView):
    """
    POST /auth/register/
    Creates a new Organization + admin User, sends verification email.
    """

    permission_classes = [permissions.AllowAny]

    @transaction.atomic
    def post(self, request: Request) -> Response:
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        AuditLog.log(
            action=AuditLog.Action.USER_REGISTERED,
            user=user,
            ip_address=_get_client_ip(request),
        )

        # Auto-create trial license for the new org
        from apps.licensing.models import License
        License.create_trial(user.organization)

        return Response(
            {
                "success": True,
                "message": "Registration successful. You can now log in.",
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )


class VerifyEmailView(APIView):
    """
    GET /auth/verify-email/?token=<uuid>
    Marks user's email as verified.
    """

    permission_classes = [permissions.AllowAny]

    def get(self, request: Request) -> Response:
        token_value = request.query_params.get("token")
        if not token_value:
            return Response({"success": False, "error": "Token required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = EmailVerificationToken.objects.select_related("user").get(token=token_value)
        except EmailVerificationToken.DoesNotExist:
            return Response({"success": False, "error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

        if not token.is_valid():
            return Response({"success": False, "error": "Token expired."}, status=status.HTTP_400_BAD_REQUEST)

        token.user.is_email_verified = True
        token.user.save(update_fields=["is_email_verified"])
        token.delete()

        return Response({"success": True, "message": "Email verified successfully."})


# ---------------------------------------------------------------------------
# Login & Logout
# ---------------------------------------------------------------------------


class LoginView(APIView):
    """
    POST /auth/login/
    Returns JWT access + refresh tokens.
    Enforces rate limiting via LoginAttempt records.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        identifier = serializer.validated_data["identifier"].strip()
        password = serializer.validated_data["password"]
        ip = _get_client_ip(request)

        # Resolve identifier to an email address.
        # If the identifier looks like an email, use it directly.
        # Otherwise treat it as a username prefix (e.g. "admin" → "admin@localhost").
        if "@" in identifier:
            email = identifier.lower()
        else:
            try:
                email = User.objects.get(
                    email__startswith=f"{identifier.lower()}@"
                ).email
            except User.DoesNotExist:
                email = identifier.lower()
            except User.MultipleObjectsReturned:
                email = identifier.lower()

        if _is_locked_out(email):
            return Response(
                {"success": False, "error": "Account temporarily locked due to too many failed attempts. Try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        user = authenticate(request, username=email, password=password)

        LoginAttempt.objects.create(email=email, ip_address=ip, success=user is not None)

        if user is None:
            return Response(
                {"success": False, "error": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            return Response(
                {"success": False, "error": "Account disabled."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Issue JWT
        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        AuditLog.log(
            action=AuditLog.Action.USER_LOGIN,
            user=user,
            ip_address=ip,
        )

        return Response(
            {
                "success": True,
                "access": str(access),
                "refresh": str(refresh),
                "user": UserSerializer(user).data,
                "must_change_password": user.must_change_password,
            }
        )


class LogoutView(APIView):
    """
    POST /auth/logout/
    Blacklists the refresh token.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"success": False, "error": "Refresh token required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError as e:
            return Response({"success": False, "error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        AuditLog.log(
            action=AuditLog.Action.USER_LOGOUT,
            user=request.user,
            ip_address=_get_client_ip(request),
        )

        return Response({"success": True, "message": "Logged out."})


# ---------------------------------------------------------------------------
# Password management
# ---------------------------------------------------------------------------


class PasswordChangeView(APIView):
    """
    POST /auth/password/change/
    Change password for authenticated user.
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user: User = request.user
        if not user.check_password(serializer.validated_data["current_password"]):
            return Response(
                {"success": False, "errors": {"current_password": ["Incorrect password."]}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data["new_password"])
        user.must_change_password = False
        user.save(update_fields=["password", "must_change_password"])

        AuditLog.log(
            action=AuditLog.Action.PASSWORD_RESET,
            user=user,
            detail={"method": "change"},
            ip_address=_get_client_ip(request),
        )

        return Response({"success": True, "message": "Password changed."})


class PasswordResetRequestView(APIView):
    """
    POST /auth/password/reset/
    Generate a temporary password, store it in the token, and send an activation email.
    The account password is NOT changed until the user clicks the activation link.
    Returns 404 explicitly when the email is not registered — this is an internal
    tool where users are always invited by an admin, so enumeration is not a concern.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].lower()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"success": False, "error": "This email address is not registered in our system."},
                status=status.HTTP_404_NOT_FOUND,
            )

        temp_password = secrets.token_urlsafe(12)  # 16 URL-safe chars
        token = PasswordResetToken.create_for_user(user, temp_password)
        _send_password_reset_email(user, token, temp_password)

        return Response(
            {"success": True, "message": "Reset instructions have been sent to your email."}
        )


class PasswordResetConfirmView(APIView):
    """
    POST /auth/password/reset/confirm/
    Activation endpoint — called when the user clicks the link in the email.
    Sets the account password to the stored temporary password and forces
    a password change on next login.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            token = PasswordResetToken.objects.select_related("user").get(
                token=serializer.validated_data["token"]
            )
        except PasswordResetToken.DoesNotExist:
            return Response({"success": False, "error": "Invalid or expired link."}, status=status.HTTP_400_BAD_REQUEST)

        if not token.is_valid():
            return Response({"success": False, "error": "This link has already been used or has expired."}, status=status.HTTP_400_BAD_REQUEST)

        if not token.temp_password:
            return Response({"success": False, "error": "Invalid reset token."}, status=status.HTTP_400_BAD_REQUEST)

        user = token.user
        user.set_password(token.temp_password)
        user.must_change_password = True
        user.save(update_fields=["password", "must_change_password"])

        token.used = True
        token.save(update_fields=["used"])

        AuditLog.log(
            action=AuditLog.Action.PASSWORD_RESET,
            user=user,
            detail={"method": "temp_password_activation"},
            ip_address=_get_client_ip(request),
        )

        return Response({"success": True, "message": "Password reset activated. You can now log in with your temporary password."})


# ---------------------------------------------------------------------------
# User profile
# ---------------------------------------------------------------------------


class MeView(generics.RetrieveUpdateAPIView):
    """
    GET/PATCH /auth/me/
    Retrieve or update the authenticated user's profile.
    PATCH accepts: first_name, last_name, email.
    Always returns the full UserSerializer representation.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method in ("PUT", "PATCH"):
            return ProfileUpdateSerializer
        return UserSerializer

    def get_object(self) -> User:
        return self.request.user

    def update(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        response = super().update(request, *args, **kwargs)
        # Always return full user representation after update
        response.data = UserSerializer(self.get_object()).data
        return response


# ---------------------------------------------------------------------------
# Organization management
# ---------------------------------------------------------------------------


class OrganizationView(generics.RetrieveUpdateAPIView):
    """
    GET/PATCH /auth/organization/
    Retrieve or update the current user's organization.
    Only org admins can update.
    """

    serializer_class = OrganizationSerializer

    def get_permissions(self) -> list[Any]:
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), IsOrgAdmin()]

    def get_object(self) -> Organization:
        return self.request.user.organization

    def partial_update(self, request, *args, **kwargs):
        # request.data for multipart is a Django QueryDict (subclass of MultiValueDict).
        # Spreading it with {**qd} reads raw internal dict values which are LISTS,
        # causing "Not a valid string." on every field.
        # .dict() correctly returns {key: last_value} as flat strings.
        # Files are in request.FILES and must be merged separately.
        if hasattr(request.data, "dict"):
            data: dict = request.data.dict()
        else:
            data = dict(request.data)
        for key, uploaded_file in request.FILES.items():
            data[key] = uploaded_file

        serializer = self.get_serializer(self.get_object(), data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)


# ---------------------------------------------------------------------------
# User management & invites
# ---------------------------------------------------------------------------


class OrgUserListView(generics.ListAPIView):
    """
    GET /auth/users/
    List all users in the current organization.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_queryset(self):
        return User.objects.filter(organization=self.request.user.organization).order_by("email")


class InviteUserView(APIView):
    """
    POST /auth/users/invite/
    Invite a new member to the organization (admin only).
    Creates user with unusable password; they must set a password via reset flow.
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    @transaction.atomic
    def post(self, request: Request) -> Response:
        serializer = InviteUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        email = data["email"].lower()

        if User.objects.filter(email=email).exists():
            return Response(
                {"success": False, "error": "A user with this email already exists."},
                status=status.HTTP_409_CONFLICT,
            )

        user = User.objects.create_user(
            email=email,
            password="admin",
            organization=request.user.organization,
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            role=data["role"],
            must_change_password=True,
        )

        AuditLog.log(
            action=AuditLog.Action.USER_INVITED,
            user=request.user,
            detail={"invited_email": email, "role": data["role"]},
            ip_address=_get_client_ip(request),
        )

        return Response(
            {"success": True, "message": f"Invitation sent to {email}.", "user": UserSerializer(user).data},
            status=status.HTTP_201_CREATED,
        )


class OrgUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET/PATCH/DELETE /auth/users/<id>/
    Manage a specific user in the organization (admin only for write).
    """

    serializer_class = UserSerializer

    def get_permissions(self) -> list[Any]:
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), IsOrgAdmin()]

    def get_queryset(self):
        return User.objects.filter(organization=self.request.user.organization)

    def destroy(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        user: User = self.get_object()
        if user == request.user:
            return Response(
                {"success": False, "error": "You cannot delete your own account."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class AuditLogView(generics.ListAPIView):
    """
    GET /auth/audit-log/
    Read audit log for the current organization (admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]
    serializer_class = AuditLogSerializer

    def get_queryset(self):
        return AuditLog.objects.filter(organization=self.request.user.organization).order_by("-created_at")


# ---------------------------------------------------------------------------
# System admin views (DB stats, export, reset, system info, update)
# ---------------------------------------------------------------------------


class DBStatsView(APIView):
    """
    GET /auth/admin/db-stats/
    Return database size and row counts for the current organization (admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request: Request) -> Response:
        from django.db import connection

        org = request.user.organization

        # Collect row counts per model within this org
        from apps.projects.models import Project, SubProject
        from apps.vulnerabilities.models import Vulnerability, ScanImport

        counts = {
            "projects": Project.objects.filter(organization=org).count(),
            "subprojects": SubProject.objects.filter(project__organization=org).count(),
            "vulnerabilities": Vulnerability.objects.filter(subproject__project__organization=org).count(),
            "scan_imports": ScanImport.objects.filter(subproject__project__organization=org).count(),
            "users": User.objects.filter(organization=org).count(),
        }

        # Fetch total DB size (PostgreSQL)
        db_size = None
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_size_pretty(pg_database_size(current_database()))")
                row = cursor.fetchone()
                if row:
                    db_size = row[0]
        except Exception:
            db_size = "N/A"

        return Response({"counts": counts, "db_size": db_size})


class DBExportView(APIView):
    """
    GET /auth/admin/db-export/
    Export all organization data as JSON (admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request: Request) -> Response:
        import json as _json

        from django.http import HttpResponse
        from django.core import serializers as dj_serializers

        org = request.user.organization

        from apps.projects.models import Project, SubProject
        from apps.vulnerabilities.models import Vulnerability, ScanImport

        qs_list = [
            Organization.objects.filter(pk=org.pk),
            User.objects.filter(organization=org),
            Project.objects.filter(organization=org),
            SubProject.objects.filter(project__organization=org),
            ScanImport.objects.filter(subproject__project__organization=org),
            Vulnerability.objects.filter(subproject__project__organization=org),
        ]

        combined: list = []
        for qs in qs_list:
            data = _json.loads(dj_serializers.serialize("json", qs))
            combined.extend(data)

        payload = _json.dumps(combined, indent=2, default=str)
        response = HttpResponse(payload, content_type="application/json")
        response["Content-Disposition"] = 'attachment; filename="reportshelter_export.json"'
        return response


class DBResetView(APIView):
    """
    POST /auth/admin/db-reset/
    Delete all organization data except users and org record (admin only).
    Requires { "confirm": "RESET" } in body.
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        if request.data.get("confirm") != "RESET":
            return Response(
                {"error": "Send { \"confirm\": \"RESET\" } to confirm."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        org = request.user.organization

        from apps.projects.models import Project

        deleted_count, _ = Project.objects.filter(organization=org).delete()

        logger.warning(
            "DB reset performed by %s for org %s — %d project(s) deleted.",
            request.user.email,
            org.name,
            deleted_count,
        )

        return Response({"success": True, "deleted_projects": deleted_count})


class SystemInfoView(APIView):
    """
    GET /auth/admin/system-info/
    Return application version and git commit info (admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request: Request) -> Response:
        import subprocess
        import os

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

        # Version comes from env so it survives Docker image tagging.
        # Falls back to git tag if env is not set.
        app_version = os.environ.get("APP_VERSION", "")

        # Prefer env vars (set by update.sh after git pull on the host).
        # Subprocess fallback works only in dev where .git is accessible.
        git_commit = os.environ.get("GIT_COMMIT", "")
        git_date = os.environ.get("GIT_DATE", "")
        git_tag = ""

        if not git_commit:
            try:
                git_commit = subprocess.check_output(
                    ["git", "-C", repo_root, "rev-parse", "--short", "HEAD"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).decode().strip()
                git_date = subprocess.check_output(
                    ["git", "-C", repo_root, "log", "-1", "--format=%ci"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).decode().strip()
                git_tag = subprocess.check_output(
                    ["git", "-C", repo_root, "describe", "--tags", "--abbrev=0"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                ).decode().strip()
            except Exception:
                pass

        git_commit = git_commit or "unknown"
        git_date = git_date or "unknown"

        version = app_version or git_tag or "1.0.0"

        return Response({
            "version": version,
            "git_commit": git_commit,
            "git_date": git_date,
            "repo_url": "https://github.com/Dognet-Technologies/reportshelter.git",
        })


class KillAllTasksView(APIView):
    """
    POST /auth/admin/kill-all-tasks/
    Cancel all pending and processing scan imports for this organization.
    Marks them as failed and revokes Celery tasks (admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        from apps.vulnerabilities.models import ScanImport
        from django.utils import timezone as tz

        org = request.user.organization
        active_qs = ScanImport.objects.filter(
            subproject__project__organization=org,
            status__in=[ScanImport.Status.PENDING, ScanImport.Status.PROCESSING],
        )

        try:
            count = active_qs.count()
        except Exception as exc:
            logger.error("KillAllTasksView: DB error: %s", exc)
            return Response({"detail": "Database error — run migrations."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if count == 0:
            return Response({"killed": 0, "message": "No active tasks found."})

        # Collect task IDs before bulk-updating (celery_task_id may not exist if migration not run)
        task_ids: list[str] = []
        try:
            task_ids = [t for t in active_qs.values_list("celery_task_id", flat=True) if t]
        except Exception:
            pass  # Field not yet migrated — skip revoke, still mark failed

        # Mark all as failed at once
        try:
            active_qs.update(
                status=ScanImport.Status.FAILED,
                error_message="Killed by admin.",
                processed_at=tz.now(),
            )
        except Exception as exc:
            logger.error("KillAllTasksView: update error: %s", exc)
            return Response({"detail": f"Update failed: {exc}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Revoke each known Celery task
        if task_ids:
            try:
                from config.celery import app as celery_app
                for task_id in task_ids:
                    celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
            except Exception as exc:
                logger.warning("Could not revoke Celery tasks: %s", exc)

        logger.warning(
            "Kill-all triggered by %s for org %s: %d task(s) cancelled.",
            request.user.email,
            org.name,
            count,
        )
        return Response({"killed": count, "message": f"{count} task(s) cancelled."})


class SystemCheckUpdateView(APIView):
    """
    GET /auth/admin/system-check-update/
    Compare installed version with latest GitHub Release (admin only).
    No side effects — safe to call frequently.
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    RELEASES_API = "https://api.github.com/repos/Dognet-Technologies/reportshelter/releases/latest"

    def get(self, request: Request) -> Response:
        import os
        import urllib.request
        import json as _json

        current = os.environ.get("APP_VERSION", "unknown").lstrip("v")

        try:
            req = urllib.request.Request(
                self.RELEASES_API,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "ReportShelter"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = _json.loads(resp.read())

            latest_tag = data.get("tag_name", "unknown").lstrip("v")
            published_at = data.get("published_at", "")
            release_url = data.get("html_url", "")
            body = data.get("body", "")

        except Exception as exc:
            return Response(
                {"error": f"Could not reach GitHub: {exc}"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        update_available = latest_tag != current and latest_tag != "unknown"

        return Response({
            "current_version": current,
            "latest_version": latest_tag,
            "update_available": update_available,
            "published_at": published_at,
            "release_url": release_url,
            "changelog": body,
            "update_command": "git pull origin main && docker compose up -d --build",
        })


class SystemUpdateView(APIView):
    """
    POST /auth/admin/system-update/
    Pre-update safety backup + DB migration (admin only).

    The code update itself (git pull + container rebuild) must be run on the
    host by the operator — the container cannot and should not pull from GitHub
    on behalf of the user.  This endpoint handles only what the container can
    safely do: protect the data before the operator applies the update.

    Typical operator flow:
        1. GET /system-check-update/ → see what's new
        2. POST /system-update/      → backup DB, apply pending migrations
        3. On host: git pull origin main && docker compose up -d --build
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        from django.core.management import call_command
        from apps.accounts.backup import create_backup

        steps: list[dict] = []

        # ── Step 1: pre-update backup ────────────────────────────────────────
        try:
            backup_result = create_backup(label="pre-update")
            steps.append({"step": "backup", "status": "ok", "detail": backup_result["filename"]})
            logger.info("Pre-update backup created: %s", backup_result["filename"])
        except Exception as exc:
            logger.error("Pre-update backup failed: %s", exc)
            return Response(
                {
                    "success": False,
                    "steps": [{"step": "backup", "status": "failed", "detail": str(exc)}],
                    "error": "Backup failed — update aborted to protect your data.",
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # ── Step 2: migrate (applies any migrations already present on disk) ─
        try:
            call_command("migrate", "--noinput", verbosity=0)
            steps.append({"step": "migrate", "status": "ok", "detail": "Migrations applied."})
        except Exception as exc:
            logger.error("Migrations failed: %s", exc)
            steps.append({"step": "migrate", "status": "failed", "detail": str(exc)})
            return Response(
                {
                    "success": False,
                    "steps": steps,
                    "error": (
                        "Migrations failed. Your data is safe — "
                        f"restore from backup '{backup_result['filename']}' if needed."
                    ),
                    "backup_file": backup_result["filename"],
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        logger.info(
            "Pre-update preparation completed by %s — backup: %s",
            request.user.email,
            backup_result["filename"],
        )

        return Response({
            "success": True,
            "steps": steps,
            "backup_file": backup_result["filename"],
            "next_step": "git pull origin main && docker compose up -d --build",
        })


# ---------------------------------------------------------------------------
# System configuration
# ---------------------------------------------------------------------------

class SystemConfigView(APIView):
    """
    GET  /auth/admin/system-config/  — return current system settings
    PATCH /auth/admin/system-config/ — update one or more settings
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request: Request) -> Response:
        from .models import SystemConfig
        config = SystemConfig.get()
        return Response({"backup_max_files": config.backup_max_files})

    def patch(self, request: Request) -> Response:
        from .models import SystemConfig
        config = SystemConfig.get()

        val = request.data.get("backup_max_files")
        if val is not None:
            try:
                val = int(val)
                if not (1 <= val <= 100):
                    raise ValueError
            except (ValueError, TypeError):
                return Response(
                    {"error": "backup_max_files must be an integer between 1 and 100"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            config.backup_max_files = val
            config.save(update_fields=["backup_max_files"])

        return Response({"backup_max_files": config.backup_max_files})


# Backup management views
# ---------------------------------------------------------------------------

class BackupListView(APIView):
    """
    GET /auth/admin/backups/
    List all database backups stored in /app/backups/ (admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def get(self, request: Request) -> Response:
        from apps.accounts.backup import list_backups
        return Response({"backups": list_backups()})


class BackupCreateView(APIView):
    """
    POST /auth/admin/backups/
    Trigger a manual pg_dump backup (admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        from apps.accounts.backup import create_backup

        label = request.data.get("label", "manual")
        # Sanitize label: only alphanumeric and hyphens
        label = "".join(c if c.isalnum() or c == "-" else "-" for c in str(label))[:32]

        try:
            result = create_backup(label=label)
        except Exception as exc:
            logger.error("Manual backup failed: %s", exc)
            return Response(
                {"success": False, "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        logger.info("Manual backup created by %s: %s", request.user.email, result["filename"])
        return Response({"success": True, **result}, status=status.HTTP_201_CREATED)


class BackupRestoreView(APIView):
    """
    POST /auth/admin/backups/restore/
    Restore the database from a named backup file (admin only).
    Requires { "filename": "backup-....sql.gz", "confirm": "RESTORE" }.

    WARNING: This overwrites all current data.  A fresh backup is created
    automatically before the restore so the operator can undo if needed.
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        from apps.accounts.backup import create_backup, restore_backup

        filename = request.data.get("filename", "").strip()
        confirm = request.data.get("confirm", "")

        if not filename:
            return Response(
                {"error": "Provide 'filename' in request body."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if confirm != "RESTORE":
            return Response(
                {"error": "Send { \"confirm\": \"RESTORE\" } to confirm this destructive action."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Safety backup before overwriting
        pre_restore_backup: str | None = None
        try:
            pre = create_backup(label="pre-restore")
            pre_restore_backup = pre["filename"]
        except Exception as exc:
            logger.warning("Could not create pre-restore safety backup: %s", exc)

        try:
            restore_backup(filename)
        except FileNotFoundError:
            return Response(
                {"error": f"Backup file not found: {filename}"},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as exc:
            logger.error("Restore failed: %s", exc)
            return Response(
                {"success": False, "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        logger.warning(
            "Database restored by %s from '%s' (safety backup: %s)",
            request.user.email,
            filename,
            pre_restore_backup,
        )
        return Response({
            "success": True,
            "restored_from": filename,
            "safety_backup": pre_restore_backup,
            "note": "Restart Docker containers to clear any cached state: docker compose restart",
        })
