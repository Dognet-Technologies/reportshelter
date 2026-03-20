"""
DRF permission classes for license enforcement.
"""

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

from .models import SALES_CONTACT


class HasActiveLicense(BasePermission):
    """
    Grants access only when the organization's license is TRIAL_ACTIVE or PRO_ACTIVE.
    Applied to every write operation: project creation, scan import, report export.
    """

    message = (
        "Your license has expired or is invalid. "
        "This feature is disabled. "
        f"To purchase or renew a license contact {SALES_CONTACT}."
    )

    def has_permission(self, request: Request, view: APIView) -> bool:
        # Fast path: middleware already attached the license object.
        license_obj = getattr(request, "license", None)
        if license_obj is None:
            # Fallback: direct DB query (tests / missing middleware).
            try:
                license_obj = request.user.organization.license
                license_obj.refresh_status()
            except Exception:
                return False
        return license_obj.is_active
