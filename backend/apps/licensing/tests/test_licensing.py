"""
Unit tests for the licensing app: trial logic, status transitions,
middleware, permission enforcement.
"""

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.models import Organization, User
from apps.licensing.models import License, LicenseStatus


@pytest.fixture
def org(db) -> Organization:
    return Organization.objects.create(name="Test Org", slug="test-lic-org")


@pytest.fixture
def admin_user(db, org) -> User:
    user = User.objects.create_user(
        email="admin@lic.com",
        password="SecurePass123!",
        organization=org,
        role=User.Role.ADMIN,
        is_email_verified=True,
    )
    return user


@pytest.fixture
def trial_license(db, org) -> License:
    return License.create_trial(org)


@pytest.fixture
def auth_client(db, admin_user) -> APIClient:
    client = APIClient()
    url = reverse("accounts:login")
    resp = client.post(url, {"identifier": "admin@lic.com", "password": "SecurePass123!"}, format="json")
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")
    return client


# ---------------------------------------------------------------------------
# Model logic
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestLicenseModel:
    def test_create_trial_sets_correct_dates(self, org):
        lic = License.create_trial(org)
        assert lic.status == LicenseStatus.TRIAL_ACTIVE
        assert lic.trial_started_at is not None
        assert lic.trial_expires_at is not None
        delta = lic.trial_expires_at - lic.trial_started_at
        assert delta.days == 30

    def test_is_active_when_trial_active(self, trial_license):
        assert trial_license.is_active is True

    def test_refresh_status_expires_trial(self, trial_license):
        trial_license.trial_expires_at = timezone.now() - timedelta(days=1)
        trial_license.save()
        trial_license.refresh_status()
        trial_license.refresh_from_db()
        assert trial_license.status == LicenseStatus.TRIAL_EXPIRED

    def test_is_active_false_when_expired(self, trial_license):
        trial_license.trial_expires_at = timezone.now() - timedelta(days=1)
        trial_license.save()
        trial_license.refresh_status()
        trial_license.refresh_from_db()
        assert trial_license.is_active is False

    def test_days_remaining_trial(self, trial_license):
        remaining = trial_license.days_remaining
        assert remaining is not None
        assert 28 <= remaining <= 30

    def test_activate_pro(self, trial_license):
        expires = timezone.now() + timedelta(days=365)
        trial_license.activate_pro("TEST-KEY-12345", expires_at=expires)
        trial_license.refresh_from_db()
        assert trial_license.status == LicenseStatus.PRO_ACTIVE
        assert trial_license.license_key == "TEST-KEY-12345"

    def test_invalidate(self, trial_license):
        trial_license.invalidate()
        trial_license.refresh_from_db()
        assert trial_license.status == LicenseStatus.INVALID

    def test_invalid_stays_invalid_after_refresh(self, trial_license):
        trial_license.invalidate()
        trial_license.refresh_status()
        trial_license.refresh_from_db()
        assert trial_license.status == LicenseStatus.INVALID


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestLicenseAPI:
    def test_status_returns_license_info(self, auth_client, trial_license):
        url = reverse("licensing:status")
        resp = auth_client.get(url)
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["success"] is True
        assert resp.data["license"]["status"] == LicenseStatus.TRIAL_ACTIVE

    def test_status_requires_auth(self):
        client = APIClient()
        url = reverse("licensing:status")
        resp = client.get(url)
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_activate_not_configured_returns_503(self, auth_client, trial_license):
        url = reverse("licensing:activate")
        resp = auth_client.post(url, {"license_key": "TESTKEY-1234-ABCD"}, format="json")
        # WPLicenseClient raises NotImplementedError → 503
        assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    def test_activate_short_key_rejected(self, auth_client, trial_license):
        url = reverse("licensing:activate")
        resp = auth_client.post(url, {"license_key": "short"}, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST
