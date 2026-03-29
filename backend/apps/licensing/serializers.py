"""Serializers for the licensing app."""

import re

from rest_framework import serializers

from .models import License, LicenseStatus

# RS-XXXX-XXXX-XXXX-XXXX  (case-insensitive, alphanumeric chunks)
_LICENSE_KEY_RE = re.compile(r"^RS-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$", re.IGNORECASE)


class LicenseSerializer(serializers.ModelSerializer):
    """Read-only license info returned to the frontend."""

    days_remaining = serializers.IntegerField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    is_trial = serializers.BooleanField(read_only=True)
    is_expired = serializers.BooleanField(read_only=True)

    class Meta:
        model = License
        fields = [
            "status",
            "license_key",
            "trial_started_at",
            "trial_expires_at",
            "pro_activated_at",
            "pro_expires_at",
            "last_checked_at",
            "days_remaining",
            "is_active",
            "is_trial",
            "is_expired",
        ]
        read_only_fields = fields


class ActivateLicenseSerializer(serializers.Serializer):
    """Payload to activate a PRO license key."""

    license_key = serializers.CharField(max_length=255, min_length=10)

    def validate_license_key(self, value: str) -> str:
        return value.upper()
