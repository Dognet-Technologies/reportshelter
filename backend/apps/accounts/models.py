"""
Models for the accounts app.
Defines Organization, User with Argon2 hashing, email verification,
password reset tokens, audit log entries, and login attempt tracking.
"""

import secrets
import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class Organization(models.Model):
    """
    Top-level tenant. All users, projects, and licenses belong to one Organization.
    """

    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    address = models.TextField(blank=True)
    phone = models.CharField(max_length=64, blank=True)
    email = models.EmailField(blank=True)
    website = models.URLField(blank=True)
    vat_number = models.CharField(max_length=64, blank=True, verbose_name="VAT / P.IVA")
    legal_disclaimer = models.TextField(blank=True)

    # Branding — stored as file paths
    logo = models.ImageField(upload_to="org/logos/", blank=True, null=True)

    # Report defaults (overridden per-project)
    primary_color = models.CharField(max_length=7, default="#3b82f6")
    secondary_color = models.CharField(max_length=7, default="#64748b")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Organization"
        verbose_name_plural = "Organizations"

    def __str__(self) -> str:
        return self.name


class UserManager(BaseUserManager["User"]):
    """Custom manager for email-based authentication."""

    def create_user(
        self,
        email: str,
        password: str,
        organization: Organization,
        **extra_fields,
    ) -> "User":
        """Create and save a regular user."""
        if not email:
            raise ValueError("Email is required.")
        email = self.normalize_email(email)
        user = self.model(email=email, organization=organization, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str, **extra_fields) -> "User":
        """Create a superuser (for admin access only)."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_email_verified", True)

        # Superusers get a synthetic organization
        org, _ = Organization.objects.get_or_create(
            slug="superadmin",
            defaults={"name": "Superadmin"},
        )
        return self.create_user(email, password, organization=org, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model with email authentication.
    Password is hashed with Argon2 (via PASSWORD_HASHERS setting).
    """

    class Role(models.TextChoices):
        ADMIN = "admin", "Admin"
        MEMBER = "member", "Member"

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="users",
    )
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.MEMBER)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)

    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self) -> str:
        return self.email

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip() or self.email

    @property
    def is_org_admin(self) -> bool:
        return self.role == self.Role.ADMIN


def _email_token_expiry() -> "timezone.datetime":
    return timezone.now() + timedelta(hours=24)


def _password_reset_expiry() -> "timezone.datetime":
    return timezone.now() + timedelta(hours=1)


class EmailVerificationToken(models.Model):
    """One-time token sent to verify a user's email address."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="email_token")
    token = models.UUIDField(default=uuid.uuid4, unique=True, db_index=True)
    expires_at = models.DateTimeField(default=_email_token_expiry)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Email Verification Token"

    def is_valid(self) -> bool:
        """Return True if the token has not expired."""
        return timezone.now() < self.expires_at

    def __str__(self) -> str:
        return f"EmailToken({self.user.email})"


class PasswordResetToken(models.Model):
    """
    Short-lived token (1h) for password reset flows.
    One active token per user; creating a new one invalidates the previous.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_tokens")
    token = models.CharField(max_length=64, unique=True, db_index=True)
    expires_at = models.DateTimeField(default=_password_reset_expiry)
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Password Reset Token"

    @classmethod
    def create_for_user(cls, user: User) -> "PasswordResetToken":
        """Invalidate existing tokens and create a fresh one."""
        cls.objects.filter(user=user, used=False).update(used=True)
        return cls.objects.create(
            user=user,
            token=secrets.token_urlsafe(48),
        )

    def is_valid(self) -> bool:
        return not self.used and timezone.now() < self.expires_at

    def __str__(self) -> str:
        return f"PasswordReset({self.user.email})"


class LoginAttempt(models.Model):
    """
    Tracks failed login attempts per email for rate limiting / lockout.
    """

    email = models.EmailField(db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    attempted_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)

    class Meta:
        verbose_name = "Login Attempt"
        ordering = ["-attempted_at"]

    def __str__(self) -> str:
        status = "OK" if self.success else "FAIL"
        return f"[{status}] {self.email} @ {self.attempted_at:%Y-%m-%d %H:%M}"


class AuditLog(models.Model):
    """
    Immutable audit trail for sensitive actions.
    """

    class Action(models.TextChoices):
        USER_LOGIN = "user_login", "User Login"
        USER_LOGOUT = "user_logout", "User Logout"
        USER_REGISTERED = "user_registered", "User Registered"
        PASSWORD_RESET = "password_reset", "Password Reset"
        USER_INVITED = "user_invited", "User Invited"
        PROJECT_CREATED = "project_created", "Project Created"
        PROJECT_EXPORTED = "project_exported", "Project Exported"
        FILE_IMPORTED = "file_imported", "File Imported"
        LICENSE_ACTIVATED = "license_activated", "License Activated"
        LICENSE_CHECKED = "license_checked", "License Checked"

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
    )
    action = models.CharField(max_length=64, choices=Action.choices)
    detail = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.action} — {self.user} @ {self.created_at:%Y-%m-%d %H:%M}"

    @classmethod
    def log(
        cls,
        action: str,
        user: "User | None" = None,
        organization: "Organization | None" = None,
        detail: "dict | None" = None,
        ip_address: "str | None" = None,
    ) -> "AuditLog":
        """Convenience factory to create an audit entry."""
        return cls.objects.create(
            action=action,
            user=user,
            organization=organization or (user.organization if user else None),
            detail=detail or {},
            ip_address=ip_address,
        )
