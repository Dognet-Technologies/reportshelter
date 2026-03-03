"""
Permission classes for the projects app.
"""

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

from .models import Project


class IsProjectMember(BasePermission):
    """
    Allow access only if the user belongs to the project's organization.
    IDOR protection: verifies ownership on every object access.
    """

    message = "You do not have access to this project."

    def has_object_permission(self, request: Request, view: APIView, obj: Project) -> bool:
        return obj.organization_id == request.user.organization_id


class IsProjectLockHolder(BasePermission):
    """
    Allow write access only if the user holds the project lock (or lock is expired/absent).
    """

    message = "Project is locked by another user."

    def has_object_permission(self, request: Request, view: APIView, obj: Project) -> bool:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True
        try:
            lock = obj.lock
            if lock.is_expired():
                lock.delete()
                return True
            return lock.locked_by_id == request.user.pk
        except Project.lock.RelatedObjectDoesNotExist:
            return True
