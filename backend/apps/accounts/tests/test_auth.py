"""
Unit tests for accounts app: registration, login, password reset,
email verification, rate limiting.
"""

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.models import (
    AuditLog,
    EmailVerificationToken,
    LoginAttempt,
    Organization,
    PasswordResetToken,
    User,
)


@pytest.fixture
def api_client() -> APIClient:
    return APIClient()


@pytest.fixture
def org(db) -> Organization:
    return Organization.objects.create(name="Test Org", slug="test-org")


@pytest.fixture
def user(db, org) -> User:
    return User.objects.create_user(
        email="test@example.com",
        password="SecurePass123!",
        organization=org,
        role=User.Role.ADMIN,
        is_email_verified=True,
    )


@pytest.fixture
def auth_client(api_client, user) -> APIClient:
    """Authenticated client with valid JWT."""
    url = reverse("accounts:login")
    resp = api_client.post(url, {"email": "test@example.com", "password": "SecurePass123!"}, format="json")
    assert resp.status_code == status.HTTP_200_OK
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")
    return api_client


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestRegistration:
    def test_register_creates_user_and_org(self, api_client):
        url = reverse("accounts:register")
        payload = {
            "org_name": "Acme Corp",
            "email": "admin@acme.com",
            "password": "SuperSecret1234!",
            "first_name": "Alice",
        }
        resp = api_client.post(url, payload, format="json")
        assert resp.status_code == status.HTTP_201_CREATED
        assert resp.data["success"] is True
        assert User.objects.filter(email="admin@acme.com").exists()
        assert Organization.objects.filter(name="Acme Corp").exists()

    def test_register_duplicate_email_rejected(self, api_client, user):
        url = reverse("accounts:register")
        payload = {
            "org_name": "Another Org",
            "email": "test@example.com",  # same as fixture user
            "password": "SuperSecret1234!",
        }
        resp = api_client.post(url, payload, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_register_weak_password_rejected(self, api_client):
        url = reverse("accounts:register")
        payload = {
            "org_name": "Weak Corp",
            "email": "weak@example.com",
            "password": "123",
        }
        resp = api_client.post(url, payload, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_first_user_is_org_admin(self, api_client):
        url = reverse("accounts:register")
        payload = {
            "org_name": "Hero Corp",
            "email": "hero@example.com",
            "password": "HeroPass9999!!",
        }
        api_client.post(url, payload, format="json")
        user = User.objects.get(email="hero@example.com")
        assert user.role == User.Role.ADMIN


# ---------------------------------------------------------------------------
# Email Verification
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestEmailVerification:
    def test_verify_email_valid_token(self, api_client, user):
        token = EmailVerificationToken.objects.create(user=user)
        user.is_email_verified = False
        user.save()
        url = reverse("accounts:verify-email") + f"?token={token.token}"
        resp = api_client.get(url)
        assert resp.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.is_email_verified is True

    def test_verify_email_invalid_token(self, api_client):
        url = reverse("accounts:verify-email") + "?token=00000000-0000-0000-0000-000000000000"
        resp = api_client.get(url)
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_verify_email_missing_token(self, api_client):
        url = reverse("accounts:verify-email")
        resp = api_client.get(url)
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestLogin:
    def test_login_success(self, api_client, user):
        url = reverse("accounts:login")
        resp = api_client.post(url, {"email": "test@example.com", "password": "SecurePass123!"}, format="json")
        assert resp.status_code == status.HTTP_200_OK
        assert "access" in resp.data
        assert "refresh" in resp.data

    def test_login_wrong_password(self, api_client, user):
        url = reverse("accounts:login")
        resp = api_client.post(url, {"email": "test@example.com", "password": "wrong"}, format="json")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_nonexistent_user(self, api_client):
        url = reverse("accounts:login")
        resp = api_client.post(url, {"email": "nobody@example.com", "password": "pass"}, format="json")
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    def test_login_creates_audit_log(self, api_client, user):
        url = reverse("accounts:login")
        api_client.post(url, {"email": "test@example.com", "password": "SecurePass123!"}, format="json")
        assert AuditLog.objects.filter(action=AuditLog.Action.USER_LOGIN, user=user).exists()

    def test_lockout_after_max_attempts(self, api_client, user, settings):
        settings.LOGIN_MAX_ATTEMPTS = 3
        settings.LOGIN_LOCKOUT_MINUTES = 15
        url = reverse("accounts:login")
        for _ in range(3):
            api_client.post(url, {"email": "test@example.com", "password": "wrong"}, format="json")
        resp = api_client.post(url, {"email": "test@example.com", "password": "SecurePass123!"}, format="json")
        assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestLogout:
    def test_logout_blacklists_token(self, api_client, user):
        # Login to get tokens
        login_url = reverse("accounts:login")
        login_resp = api_client.post(
            login_url,
            {"email": "test@example.com", "password": "SecurePass123!"},
            format="json",
        )
        refresh = login_resp.data["refresh"]
        access = login_resp.data["access"]

        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        logout_url = reverse("accounts:logout")
        resp = api_client.post(logout_url, {"refresh": refresh}, format="json")
        assert resp.status_code == status.HTTP_200_OK

        # Refresh should now fail
        refresh_url = reverse("accounts:token-refresh")
        resp2 = api_client.post(refresh_url, {"refresh": refresh}, format="json")
        assert resp2.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# Password Reset
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestPasswordReset:
    def test_reset_request_valid_email(self, api_client, user):
        url = reverse("accounts:password-reset-request")
        resp = api_client.post(url, {"email": "test@example.com"}, format="json")
        assert resp.status_code == status.HTTP_200_OK
        assert PasswordResetToken.objects.filter(user=user).exists()

    def test_reset_request_unknown_email_still_200(self, api_client):
        url = reverse("accounts:password-reset-request")
        resp = api_client.post(url, {"email": "nobody@example.com"}, format="json")
        assert resp.status_code == status.HTTP_200_OK  # No user enumeration

    def test_reset_confirm_valid_token(self, api_client, user):
        token = PasswordResetToken.create_for_user(user)
        url = reverse("accounts:password-reset-confirm")
        payload = {
            "token": token.token,
            "new_password": "NewSuperPass9999!!",
            "confirm_password": "NewSuperPass9999!!",
        }
        resp = api_client.post(url, payload, format="json")
        assert resp.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.check_password("NewSuperPass9999!!")

    def test_reset_confirm_invalid_token(self, api_client):
        url = reverse("accounts:password-reset-confirm")
        payload = {"token": "invalid", "new_password": "NewPass9999!!", "confirm_password": "NewPass9999!!"}
        resp = api_client.post(url, payload, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    def test_reset_confirm_password_mismatch(self, api_client, user):
        token = PasswordResetToken.create_for_user(user)
        url = reverse("accounts:password-reset-confirm")
        payload = {
            "token": token.token,
            "new_password": "NewPass9999!!",
            "confirm_password": "DifferentPass9999!!",
        }
        resp = api_client.post(url, payload, format="json")
        assert resp.status_code == status.HTTP_400_BAD_REQUEST


# ---------------------------------------------------------------------------
# Me & Organization
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestProfileAndOrg:
    def test_me_returns_user_data(self, auth_client, user):
        url = reverse("accounts:me")
        resp = auth_client.get(url)
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["email"] == user.email

    def test_organization_returns_org_data(self, auth_client, user):
        url = reverse("accounts:organization")
        resp = auth_client.get(url)
        assert resp.status_code == status.HTTP_200_OK
        assert resp.data["name"] == user.organization.name

    def test_me_requires_auth(self, api_client):
        url = reverse("accounts:me")
        resp = api_client.get(url)
        assert resp.status_code == status.HTTP_401_UNAUTHORIZED
