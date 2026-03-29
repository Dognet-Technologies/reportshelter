"""
Models for the licensing app.
Manages license state per Organization: trial, PRO active/expired, invalid.

Protection layers:
  1. HMAC-SHA256 integrity hash — detects direct DB manipulation.
  2. Periodic online revalidation against the DLM server for PRO licenses.
  3. Grace period before hard-expiring when the DLM server is unreachable.
"""

import hashlib
import hmac as _hmac_module
import logging
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

TRIAL_DURATION_DAYS = 30

# How often (hours) to re-verify a PRO license against the DLM server.
_ONLINE_CHECK_INTERVAL_H = 12

# How long (hours) to tolerate DLM unreachability before hard-expiring a PRO key.
_ONLINE_GRACE_PERIOD_H = 48

# Support contact — assembled at runtime so it is not trivially grep-able.
import base64 as _b64
_SC = _b64.b64decode(b"c2FsZXNAZG9nbmV0LXRlY2hub2xvZ2llcy5vbmxpbmU=").decode()
SALES_CONTACT: str = _SC
del _b64, _SC


# ── Status choices ─────────────────────────────────────────────────────────────

class LicenseStatus(models.TextChoices):
    TRIAL_ACTIVE  = "trial_active",  "Trial Active"
    TRIAL_EXPIRED = "trial_expired", "Trial Expired"
    PRO_ACTIVE    = "pro_active",    "PRO Active"
    PRO_EXPIRED   = "pro_expired",   "PRO Expired"
    INVALID       = "invalid",       "Invalid"


# ── Model ──────────────────────────────────────────────────────────────────────

class License(models.Model):
    """
    License record tied to an Organization (one-to-one).

    Status flow:
        (created)           → TRIAL_ACTIVE  (30-day countdown)
        trial clock runs out → TRIAL_EXPIRED
        key activated        → PRO_ACTIVE
        DLM reports revoked  → PRO_EXPIRED
        integrity check fail → INVALID
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
    # Opaque token returned by the DLM /activate endpoint.
    # Used for all subsequent /validate and /deactivate calls.
    activation_token = models.CharField(max_length=255, blank=True, default="")

    trial_started_at  = models.DateTimeField(null=True, blank=True)
    trial_expires_at  = models.DateTimeField(null=True, blank=True)

    pro_activated_at  = models.DateTimeField(null=True, blank=True)
    pro_expires_at    = models.DateTimeField(null=True, blank=True)

    # Timestamps
    last_checked_at       = models.DateTimeField(null=True, blank=True)
    last_online_checked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Tamper-detection field — HMAC-SHA256 over critical fields using SECRET_KEY.
    integrity_hash = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        verbose_name = "License"
        verbose_name_plural = "Licenses"

    def __str__(self) -> str:
        return f"License({self.organization.name}) [{self.status}]"

    # ------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------

    def _compute_integrity_hash(self) -> str:
        """Return HMAC-SHA256 over the fields that define license validity."""
        key = settings.SECRET_KEY.encode("utf-8")
        msg = "|".join([
            str(self.organization_id or ""),
            self.status,
            self.license_key or "",
            str(self.trial_started_at or ""),
            str(self.trial_expires_at or ""),
            str(self.pro_activated_at or ""),
            str(self.pro_expires_at or ""),
        ]).encode("utf-8")
        return _hmac_module.new(key, msg, hashlib.sha256).hexdigest()

    def verify_integrity(self) -> bool:
        """Return True if the stored hash matches the current field values."""
        if not self.integrity_hash:
            return True  # No hash yet (pre-migration row) — trust on first access.
        return _hmac_module.compare_digest(
            self.integrity_hash,
            self._compute_integrity_hash(),
        )

    def save(self, *args, **kwargs) -> None:
        """Always recompute the integrity hash before persisting."""
        self.integrity_hash = self._compute_integrity_hash()
        update_fields = kwargs.get("update_fields")
        if update_fields is not None and "integrity_hash" not in update_fields:
            kwargs["update_fields"] = list(update_fields) + ["integrity_hash"]
        super().save(*args, **kwargs)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create_trial(cls, organization: "accounts.Organization") -> "License":  # type: ignore[name-defined]
        """Create a fresh 30-day trial license for a new organization."""
        now = timezone.now()
        return cls.objects.create(
            organization=organization,
            status=LicenseStatus.TRIAL_ACTIVE,
            trial_started_at=now,
            trial_expires_at=now + timedelta(days=TRIAL_DURATION_DAYS),
        )

    # ------------------------------------------------------------------
    # Status refresh
    # ------------------------------------------------------------------

    def refresh_status(self) -> None:
        """
        Recompute and persist the license status.

        Steps:
          1. Verify HMAC integrity — if tampered, immediately set INVALID.
          2. Compute time-based status from local fields.
          3. For PRO licenses, periodically call the DLM server to confirm the
             key has not been revoked (throttled to once per 12 h).
        """
        # ── 1. Tamper check ───────────────────────────────────────────
        if self.integrity_hash and not self.verify_integrity():
            logger.critical(
                "License integrity check FAILED for org %s — record may have been tampered with.",
                self.organization_id,
            )
            self.status = LicenseStatus.INVALID
            self.integrity_hash = ""
            self.save(update_fields=["status", "integrity_hash", "updated_at"])
            return

        now = timezone.now()
        new_status = self._compute_status(now)

        # ── 2. Periodic online revalidation for PRO ───────────────────
        if new_status in (LicenseStatus.PRO_ACTIVE, LicenseStatus.PRO_EXPIRED):
            interval = timedelta(hours=_ONLINE_CHECK_INTERVAL_H)
            needs_check = (
                self.last_online_checked_at is None
                or (now - self.last_online_checked_at) >= interval
            )
            if needs_check:
                new_status = self._validate_pro_online(now, new_status)

        if new_status != self.status:
            self.status = new_status
            self.save(update_fields=["status", "updated_at"])

    def _compute_status(self, now: "timezone.datetime") -> str:  # type: ignore[name-defined]
        if self.status == LicenseStatus.INVALID:
            return LicenseStatus.INVALID

        if self.status in (LicenseStatus.PRO_ACTIVE, LicenseStatus.PRO_EXPIRED):
            if self.pro_expires_at and now > self.pro_expires_at:
                return LicenseStatus.PRO_EXPIRED
            return LicenseStatus.PRO_ACTIVE

        if self.trial_expires_at and now > self.trial_expires_at:
            return LicenseStatus.TRIAL_EXPIRED
        return LicenseStatus.TRIAL_ACTIVE

    def _validate_pro_online(self, now: "timezone.datetime", fallback: str) -> str:  # type: ignore[name-defined]
        """
        Call the DLM API to confirm the license key is still active.
        Updates ``last_online_checked_at`` on success.
        Falls back to ``_grace_period_status`` on network/API failure.
        """
        from .wp_license_client import WPLicenseClient, WPLicenseClientError

        client = WPLicenseClient()
        if not client._configured:
            logger.warning(
                "DLM client not configured for org %s — cannot perform online license check.",
                self.organization_id,
            )
            return self._grace_period_status(now, fallback)

        if not self.activation_token:
            logger.warning(
                "No activation token for org %s — skipping online validation.",
                self.organization_id,
            )
            return fallback

        try:
            info = client.validate_license(self.activation_token)
        except (WPLicenseClientError, Exception) as exc:
            logger.warning(
                "Online license check failed for org %s: %s",
                self.organization_id, exc,
            )
            return self._grace_period_status(now, fallback)

        self.last_online_checked_at = now
        self.last_checked_at = now

        # Sync expiry date from the DLM server
        if info.expires_at:
            from django.utils.dateparse import parse_datetime
            expires = parse_datetime(info.expires_at)
            if expires:
                self.pro_expires_at = expires

        self.save(update_fields=[
            "last_online_checked_at", "last_checked_at",
            "pro_expires_at", "updated_at",
        ])

        if info.status == "active":
            return LicenseStatus.PRO_ACTIVE

        logger.warning(
            "DLM reports license '%s' as '%s' for org %s.",
            self.license_key[:8], info.status, self.organization_id,
        )
        return LicenseStatus.PRO_EXPIRED

    def _grace_period_status(self, now: "timezone.datetime", fallback: str) -> str:  # type: ignore[name-defined]
        """
        When the DLM server is unreachable, honour a grace window.
        After ``_ONLINE_GRACE_PERIOD_H`` hours without a successful check,
        the license is hard-expired to prevent indefinite offline use.
        """
        reference = self.last_online_checked_at or self.pro_activated_at
        if reference is None:
            return fallback  # No reference point yet; optimistic.

        hours_offline = (now - reference).total_seconds() / 3600.0
        if hours_offline > _ONLINE_GRACE_PERIOD_H:
            logger.warning(
                "PRO license for org %s: DLM unreachable for %.0f h (grace=%d h) → expiring.",
                self.organization_id, hours_offline, _ONLINE_GRACE_PERIOD_H,
            )
            return LicenseStatus.PRO_EXPIRED
        return fallback

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

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
        """Days left for the active trial or PRO license; None otherwise."""
        now = timezone.now()
        if self.status == LicenseStatus.TRIAL_ACTIVE and self.trial_expires_at:
            return max(0, (self.trial_expires_at - now).days)
        if self.status == LicenseStatus.PRO_ACTIVE and self.pro_expires_at:
            return max(0, (self.pro_expires_at - now).days)
        return None

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    def activate_pro(
        self,
        license_key: str,
        activation_token: str = "",
        expires_at: "timezone.datetime | None" = None,  # type: ignore[name-defined]
    ) -> None:
        """
        Transition to PRO_ACTIVE after the DLM API confirms the key.
        Stores the activation token for future validate/deactivate calls.
        Records an immediate online check timestamp so the next check
        is deferred by ``_ONLINE_CHECK_INTERVAL_H`` hours.
        """
        now = timezone.now()
        self.license_key = license_key
        self.activation_token = activation_token
        self.status = LicenseStatus.PRO_ACTIVE
        self.pro_activated_at = now
        self.pro_expires_at = expires_at
        self.last_checked_at = now
        self.last_online_checked_at = now
        self.save()

    def invalidate(self) -> None:
        """Mark license as invalid (e.g., key revoked via the deactivate endpoint)."""
        self.status = LicenseStatus.INVALID
        self.save(update_fields=["status", "updated_at"])
