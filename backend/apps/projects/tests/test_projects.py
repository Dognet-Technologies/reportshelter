"""
Tests for the projects app: Project CRUD, SubProject, lock mechanism.
"""

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.models import Organization, User
from apps.licensing.models import License
from apps.projects.models import Project, ProjectLock, SubProject


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def org() -> Organization:
    return Organization.objects.create(name="TestOrg", slug="testorg")


@pytest.fixture
def license_(org: Organization) -> License:
    return License.create_trial(org)


@pytest.fixture
def admin_user(org: Organization, license_) -> User:
    return User.objects.create_user(
        email="admin@test.com",
        password="Str0ngP@ssword!",
        organization=org,
        role=User.Role.ADMIN,
        is_email_verified=True,
    )


@pytest.fixture
def member_user(org: Organization, license_) -> User:
    return User.objects.create_user(
        email="member@test.com",
        password="Str0ngP@ssword!",
        organization=org,
        role=User.Role.MEMBER,
        is_email_verified=True,
    )


@pytest.fixture
def other_org() -> Organization:
    return Organization.objects.create(name="OtherOrg", slug="otherorg")


@pytest.fixture
def other_user(other_org: Organization) -> User:
    License.create_trial(other_org)
    return User.objects.create_user(
        email="other@test.com",
        password="Str0ngP@ssword!",
        organization=other_org,
        role=User.Role.ADMIN,
        is_email_verified=True,
    )


@pytest.fixture
def auth_client(admin_user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=admin_user)
    return client


@pytest.fixture
def member_client(member_user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=member_user)
    return client


@pytest.fixture
def other_client(other_user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=other_user)
    return client


@pytest.fixture
def project(org: Organization, admin_user: User) -> Project:
    return Project.objects.create(
        organization=org,
        title="Test Project",
        description="A test project",
        created_by=admin_user,
    )


@pytest.fixture
def subproject(project: Project, admin_user: User) -> SubProject:
    return SubProject.objects.create(
        project=project,
        title="Scan Q1",
        created_by=admin_user,
    )


# ---------------------------------------------------------------------------
# Project CRUD
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestProjectCRUD:
    def test_list_projects(self, auth_client: APIClient, project: Project) -> None:
        url = reverse("projects:project-list")
        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1

    def test_create_project(self, auth_client: APIClient) -> None:
        url = reverse("projects:project-list")
        data = {"title": "New Project", "description": "Desc", "client_name": "ClientCo"}
        response = auth_client.post(url, data, format="json")
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["title"] == "New Project"

    def test_create_project_requires_active_license(self, org: Organization, license_) -> None:
        """Project creation blocked when license is expired."""
        from datetime import timedelta
        from django.utils import timezone
        # Expire the license — must also set trial_expires_at to the past,
        # otherwise refresh_status() will recompute it as TRIAL_ACTIVE.
        license_ = org.license
        license_.trial_expires_at = timezone.now() - timedelta(days=1)
        license_.status = "trial_expired"
        license_.save()

        user = User.objects.create_user(
            email="exp@test.com",
            password="Str0ngP@ssword!",
            organization=org,
            role=User.Role.ADMIN,
            is_email_verified=True,
        )
        client = APIClient()
        client.force_authenticate(user=user)
        url = reverse("projects:project-list")
        response = client.post(url, {"title": "X"}, format="json")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_retrieve_project(self, auth_client: APIClient, project: Project) -> None:
        url = reverse("projects:project-detail", kwargs={"pk": project.pk})
        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data["title"] == project.title

    def test_update_project(self, auth_client: APIClient, project: Project) -> None:
        url = reverse("projects:project-detail", kwargs={"pk": project.pk})
        response = auth_client.patch(url, {"title": "Updated"}, format="json")
        assert response.status_code == status.HTTP_200_OK
        project.refresh_from_db()
        assert project.title == "Updated"

    def test_delete_project_by_admin(self, auth_client: APIClient, project: Project) -> None:
        url = reverse("projects:project-detail", kwargs={"pk": project.pk})
        response = auth_client.delete(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_delete_project_by_member_forbidden(
        self, member_client: APIClient, project: Project
    ) -> None:
        url = reverse("projects:project-detail", kwargs={"pk": project.pk})
        response = member_client.delete(url)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_idor_protection(self, other_client: APIClient, project: Project) -> None:
        """Other organization cannot access our project."""
        url = reverse("projects:project-detail", kwargs={"pk": project.pk})
        response = other_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_unauthenticated_denied(self, project: Project) -> None:
        client = APIClient()
        url = reverse("projects:project-list")
        response = client.get(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# SubProject
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestSubProject:
    def test_list_subprojects(
        self, auth_client: APIClient, project: Project, subproject: SubProject
    ) -> None:
        url = reverse("projects:subproject-list", kwargs={"project_pk": project.pk})
        response = auth_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1

    def test_create_subproject(self, auth_client: APIClient, project: Project) -> None:
        url = reverse("projects:subproject-list", kwargs={"project_pk": project.pk})
        response = auth_client.post(url, {"title": "Retest Q2"}, format="json")
        assert response.status_code == status.HTTP_201_CREATED
        assert SubProject.objects.filter(project=project).count() == 1

    def test_subproject_cross_org_denied(
        self, other_client: APIClient, project: Project
    ) -> None:
        url = reverse("projects:subproject-list", kwargs={"project_pk": project.pk})
        response = other_client.get(url)
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ---------------------------------------------------------------------------
# Project Lock
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestProjectLock:
    def test_acquire_lock(self, auth_client: APIClient, project: Project) -> None:
        url = reverse("projects:lock-acquire", kwargs={"pk": project.pk})
        response = auth_client.post(url)
        assert response.status_code == status.HTTP_200_OK
        assert ProjectLock.objects.filter(project=project).exists()

    def test_acquire_lock_already_held(
        self, auth_client: APIClient, member_client: APIClient, project: Project, member_user: User
    ) -> None:
        # Admin acquires lock
        ProjectLock.objects.create(project=project, locked_by=project.created_by)
        # Member tries to acquire
        url = reverse("projects:lock-acquire", kwargs={"pk": project.pk})
        response = member_client.post(url)
        assert response.status_code == status.HTTP_423_LOCKED

    def test_acquire_expired_lock(
        self, member_client: APIClient, project: Project, admin_user: User
    ) -> None:
        """Expired lock can be taken over by another user."""
        lock = ProjectLock.objects.create(project=project, locked_by=admin_user)
        # Artificially expire the lock
        expired_time = timezone.now() - timezone.timedelta(minutes=31)
        ProjectLock.objects.filter(pk=lock.pk).update(last_heartbeat=expired_time)
        url = reverse("projects:lock-acquire", kwargs={"pk": project.pk})
        response = member_client.post(url)
        assert response.status_code == status.HTTP_200_OK

    def test_heartbeat(self, auth_client: APIClient, project: Project, admin_user: User) -> None:
        ProjectLock.objects.create(project=project, locked_by=admin_user)
        url = reverse("projects:lock-heartbeat", kwargs={"pk": project.pk})
        response = auth_client.post(url)
        assert response.status_code == status.HTTP_200_OK

    def test_release_lock(self, auth_client: APIClient, project: Project, admin_user: User) -> None:
        ProjectLock.objects.create(project=project, locked_by=admin_user)
        url = reverse("projects:lock-release", kwargs={"pk": project.pk})
        response = auth_client.post(url)
        assert response.status_code == status.HTTP_200_OK
        assert not ProjectLock.objects.filter(project=project).exists()

    def test_lock_model_is_expired(self, project: Project, admin_user: User) -> None:
        lock = ProjectLock.objects.create(project=project, locked_by=admin_user)
        assert not lock.is_expired()
        # Force expiry
        expired_time = timezone.now() - timezone.timedelta(minutes=31)
        ProjectLock.objects.filter(pk=lock.pk).update(last_heartbeat=expired_time)
        lock.refresh_from_db()
        assert lock.is_expired()

    def test_update_locked_project_by_non_holder_returns_423(
        self, member_client: APIClient, project: Project, admin_user: User
    ) -> None:
        ProjectLock.objects.create(project=project, locked_by=admin_user)
        url = reverse("projects:project-detail", kwargs={"pk": project.pk})
        response = member_client.patch(url, {"title": "Hacked"}, format="json")
        assert response.status_code == status.HTTP_423_LOCKED
