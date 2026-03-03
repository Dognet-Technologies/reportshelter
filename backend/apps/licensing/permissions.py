"""
DRF permission classes for license enforcement.
"""

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView


class HasActiveLicense(BasePermission):
    """
    Grants access only if the organization's license is TRIAL_ACTIVE or PRO_ACTIVE.
    Used to gate write operations like creating projects, importing files, exporting reports.
    """

    message = "Your license has expired. Please renew to continue using this feature."

    def has_permission(self, request: Request, view: APIView) -> bool:
        license_obj = getattr(request, "license", None)
        if license_obj is None:
            return False
        return license_obj.is_active
