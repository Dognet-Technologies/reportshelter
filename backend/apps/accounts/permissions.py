"""Custom DRF permissions for the accounts app."""

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView


class IsOrgAdmin(BasePermission):
    """Allow access only to users with role='admin' in their organization."""

    message = "Only organization admins can perform this action."

    def has_permission(self, request: Request, view: APIView) -> bool:
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_org_admin
        )
