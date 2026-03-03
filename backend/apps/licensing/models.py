"""
Models for the licensing app.
Manages license state per Organization: trial, PRO active/expired, invalid.
"""

from datetime import timedelta

from django.db import models
from django.utils import timezone


class LicenseStatus(models.TextChoices):
    TRIAL_ACTIVE = "trial_active", "Trial Active"
    TRIAL_EXPIRED = "trial_expired", "Trial Expired"
    PRO_ACTIVE = "pro_active", "PRO Active"
    PRO_EXPIRED = "pro_expired", "PRO Expired"
    INVALID = "invalid", "Invalid"


TRIAL_DURATION_DAYS = 30


class License(models.Model):
    """
    License record tied to an Organization.
    One Organization has at most one License.

    Status transitions:
        (created)       → TRIAL_ACTIVE
        trial expires   → TRIAL_EXPIRED
        key activated   → PRO_ACTIVE
        pro expires     → PRO_EXPIRED
        key invalidated → INVALID
    """

    organization = models.OneToOneField(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="license",
    )
    status = models.CharField(
        max_length=32,
        choices=LicenseStatus.choices,
        default=LicenseStatus.TRIAL_ACTIVE,
    )
    license_key = models.CharField(max_length=255, blank=True, default="")

    trial_started_at = models.DateTimeField(null=True, blank=True)
    trial_expires_at = models.DateTimeField(null=True, blank=True)

    pro_activated_at = models.DateTimeField(null=True, blank=True)
    pro_expires_at = models.DateTimeField(null=True, blank=True)

    last_checked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "License"
        verbose_name_plural = "Licenses"

    def __str__(self) -> str:
        return f"License({self.organization.name}) [{self.status}]"

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create_trial(cls, organization: "accounts.Organization") -> "License":  # type: ignore[name-defined]
        """Create a fresh trial license for a new organization."""
        now = timezone.now()
        return cls.objects.create(
            organization=organization,
            status=LicenseStatus.TRIAL_ACTIVE,
            trial_started_at=now,
            trial_expires_at=now + timedelta(days=TRIAL_DURATION_DAYS),
        )

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    def refresh_status(self) -> None:
        """
        Recompute and persist the license status based on current time.
        Call this on every authenticated request (via middleware) or
        when explicitly checking the license.
        """
        now = timezone.now()
        new_status = self._compute_status(now)
        if new_status != self.status:
            self.status = new_status
            self.save(update_fields=["status", "updated_at"])

    def _compute_status(self, now: "timezone.datetime") -> str:
        if self.status == LicenseStatus.INVALID:
            return LicenseStatus.INVALID

        if self.status in (LicenseStatus.PRO_ACTIVE, LicenseStatus.PRO_EXPIRED):
            if self.pro_expires_at and now > self.pro_expires_at:
                return LicenseStatus.PRO_EXPIRED
            return LicenseStatus.PRO_ACTIVE

        # Trial path
        if self.trial_expires_at and now > self.trial_expires_at:
            return LicenseStatus.TRIAL_EXPIRED
        return LicenseStatus.TRIAL_ACTIVE

    @property
    def is_active(self) -> bool:
        """True when the license grants full access."""
        return self.status in (LicenseStatus.TRIAL_ACTIVE, LicenseStatus.PRO_ACTIVE)

    @property
    def is_trial(self) -> bool:
        return self.status == LicenseStatus.TRIAL_ACTIVE

    @property
    def is_expired(self) -> bool:
        return self.status in (LicenseStatus.TRIAL_EXPIRED, LicenseStatus.PRO_EXPIRED)

    @property
    def days_remaining(self) -> int | None:
        """Return days left for trial or PRO license; None if not applicable."""
        now = timezone.now()
        if self.status == LicenseStatus.TRIAL_ACTIVE and self.trial_expires_at:
            delta = self.trial_expires_at - now
            return max(0, delta.days)
        if self.status == LicenseStatus.PRO_ACTIVE and self.pro_expires_at:
            delta = self.pro_expires_at - now
            return max(0, delta.days)
        return None

    # ------------------------------------------------------------------
    # Activation
    # ------------------------------------------------------------------

    def activate_pro(self, license_key: str, expires_at: "timezone.datetime | None" = None) -> None:
        """
        Transition to PRO_ACTIVE after successful WP License Manager validation.
        Called by the activate_license view once the WPLicenseClient confirms the key.
        """
        self.license_key = license_key
        self.status = LicenseStatus.PRO_ACTIVE
        self.pro_activated_at = timezone.now()
        self.pro_expires_at = expires_at
        self.last_checked_at = timezone.now()
        self.save()

    def invalidate(self) -> None:
        """Mark license as invalid (e.g., key revoked remotely)."""
        self.status = LicenseStatus.INVALID
        self.save(update_fields=["status", "updated_at"])
