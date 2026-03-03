"""
Shared pytest fixtures for CyberReport Pro.

Available fixtures:
  org           — Organization instance
  admin_user    — admin User belonging to org
  member_user   — member User belonging to org
  other_org     — a second Organization (for IDOR tests)
  other_user    — User belonging to other_org
  api_client    — APIClient (unauthenticated)
  auth_client   — APIClient authenticated as admin_user
  member_client — APIClient authenticated as member_user
  project       — Project belonging to org, created by admin_user
  subproject    — SubProject inside project
  scan_import   — ScanImport (pending) inside subproject
  vulnerability — Vulnerability inside subproject
"""

import pytest
from rest_framework.test import APIClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_client(user) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=user)
    return client


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------


@pytest.fixture
def org(db):
    from apps.accounts.models import Organization
    return Organization.objects.create(name="Acme Security", slug="acme-security")


@pytest.fixture
def other_org(db):
    from apps.accounts.models import Organization
    return Organization.objects.create(name="Other Corp", slug="other-corp")


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_user(db, org):
    from apps.accounts.models import User
    return User.objects.create_user(
        email="admin@acme.com",
        password="strongpassword123",
        organization=org,
        role=User.Role.ADMIN,
        is_email_verified=True,
        first_name="Admin",
        last_name="User",
    )


@pytest.fixture
def member_user(db, org):
    from apps.accounts.models import User
    return User.objects.create_user(
        email="member@acme.com",
        password="strongpassword123",
        organization=org,
        role=User.Role.MEMBER,
        is_email_verified=True,
        first_name="Member",
        last_name="User",
    )


@pytest.fixture
def other_user(db, other_org):
    from apps.accounts.models import User
    return User.objects.create_user(
        email="attacker@other.com",
        password="strongpassword123",
        organization=other_org,
        role=User.Role.ADMIN,
        is_email_verified=True,
    )


# ---------------------------------------------------------------------------
# Licensing (Trial active)
# ---------------------------------------------------------------------------


@pytest.fixture
def active_license(db, org):
    from apps.licensing.models import License
    from django.utils import timezone
    from datetime import timedelta
    return License.objects.create(
        organization=org,
        status=License.Status.TRIAL_ACTIVE,
        trial_started_at=timezone.now(),
        trial_expires_at=timezone.now() + timedelta(days=30),
    )


# ---------------------------------------------------------------------------
# API clients
# ---------------------------------------------------------------------------


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def auth_client(admin_user):
    return _auth_client(admin_user)


@pytest.fixture
def member_client(member_user):
    return _auth_client(member_user)


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


@pytest.fixture
def project(db, org, admin_user):
    from apps.projects.models import Project
    return Project.objects.create(
        organization=org,
        created_by=admin_user,
        title="Test Pentest Project",
        client_name="Client Corp",
        client_email="contact@client.com",
    )


@pytest.fixture
def subproject(db, project, admin_user):
    from apps.projects.models import SubProject
    from datetime import date
    return SubProject.objects.create(
        project=project,
        created_by=admin_user,
        title="Q1 2025 Scan",
        scan_date=date(2025, 1, 15),
    )


# ---------------------------------------------------------------------------
# Vulnerabilities / Imports
# ---------------------------------------------------------------------------


@pytest.fixture
def scan_import(db, subproject, admin_user):
    from apps.vulnerabilities.models import ScanImport
    return ScanImport.objects.create(
        subproject=subproject,
        tool=ScanImport.Tool.NMAP,
        original_filename="scan.xml",
        imported_by=admin_user,
    )


@pytest.fixture
def vulnerability(db, subproject):
    from apps.vulnerabilities.models import Vulnerability
    return Vulnerability.objects.create(
        subproject=subproject,
        title="SQL Injection in /login",
        description="Classic SQLi via username parameter.",
        remediation="Use parameterized queries.",
        affected_host="192.168.1.1",
        affected_port="443",
        affected_service="HTTPS",
        cve_id="CVE-2023-0001",
        cvss_score=9.1,
        risk_level=Vulnerability.RiskLevel.CRITICAL,
        sources=["nmap"],
    )
