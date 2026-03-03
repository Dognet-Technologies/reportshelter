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


def _send_verification_email(user: User, token: EmailVerificationToken) -> None:
    """Send email address verification link."""
    frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173")
    verify_url = f"{frontend_url}/verify-email?token={token.token}"
    send_mail(
        subject="Verify your CyberReport Pro email",
        message=f"Hi {user.first_name or user.email},\n\nVerify your email: {verify_url}\n\nThis link expires in 24 hours.",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=True,
    )


def _send_password_reset_email(user: User, token: PasswordResetToken) -> None:
    """Send password reset link."""
    frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173")
    reset_url = f"{frontend_url}/reset-password?token={token.token}"
    send_mail(
        subject="Reset your CyberReport Pro password",
        message=f"Hi {user.first_name or user.email},\n\nReset your password: {reset_url}\n\nThis link expires in 1 hour.",
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

        # Create and send verification token
        token = EmailVerificationToken.objects.create(user=user)
        _send_verification_email(user, token)

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
                "message": "Registration successful. Please check your email to verify your account.",
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

        email = serializer.validated_data["email"].lower()
        password = serializer.validated_data["password"]
        ip = _get_client_ip(request)

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
        user.save(update_fields=["password"])

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
    Send password reset email (always returns 200 to avoid user enumeration).
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request: Request) -> Response:
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"].lower()
        try:
            user = User.objects.get(email=email)
            token = PasswordResetToken.create_for_user(user)
            _send_password_reset_email(user, token)
        except User.DoesNotExist:
            pass  # Silent — no user enumeration

        return Response(
            {"success": True, "message": "If that email is registered, a reset link has been sent."}
        )


class PasswordResetConfirmView(APIView):
    """
    POST /auth/password/reset/confirm/
    Validate token and set new password.
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
            return Response({"success": False, "error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

        if not token.is_valid():
            return Response({"success": False, "error": "Token expired or already used."}, status=status.HTTP_400_BAD_REQUEST)

        token.user.set_password(serializer.validated_data["new_password"])
        token.user.save(update_fields=["password"])
        token.used = True
        token.save(update_fields=["used"])

        AuditLog.log(
            action=AuditLog.Action.PASSWORD_RESET,
            user=token.user,
            detail={"method": "reset"},
            ip_address=_get_client_ip(request),
        )

        return Response({"success": True, "message": "Password reset successfully."})


# ---------------------------------------------------------------------------
# User profile
# ---------------------------------------------------------------------------


class MeView(generics.RetrieveUpdateAPIView):
    """
    GET/PATCH /auth/me/
    Retrieve or update the authenticated user's profile.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self) -> User:
        return self.request.user


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
            password=User.objects.make_random_password(length=40),
            organization=request.user.organization,
            first_name=data.get("first_name", ""),
            last_name=data.get("last_name", ""),
            role=data["role"],
        )

        # Send password set email (reuse reset flow)
        token = PasswordResetToken.create_for_user(user)
        frontend_url = getattr(settings, "FRONTEND_URL", "http://localhost:5173")
        setup_url = f"{frontend_url}/set-password?token={token.token}"
        send_mail(
            subject=f"You've been invited to {request.user.organization.name} on CyberReport Pro",
            message=(
                f"Hi {user.first_name or email},\n\n"
                f"You have been invited by {request.user.full_name}.\n"
                f"Set your password here: {setup_url}\n\n"
                "This link expires in 1 hour."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=True,
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
