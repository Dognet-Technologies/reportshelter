"""
License check middleware.
Refreshes license status on each authenticated request.
Does NOT block requests here — blocking is done at the view/permission level.
"""

import logging
from typing import Callable

from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)

# Paths that are always accessible regardless of license status
_EXEMPT_PREFIXES = (
    "/admin/",
    "/api/v1/auth/",
    "/api/v1/licensing/",
    "/static/",
    "/media/",
    "/ws/",
)


class LicenseCheckMiddleware:
    """
    Refreshes the organization's license status on every authenticated request.
    Attaches `request.license` for use in views and permissions.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request.license = None  # type: ignore[attr-defined]

        # Only check for authenticated users with an organization
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated and hasattr(user, "organization"):
            try:
                license_obj = user.organization.license
                license_obj.refresh_status()
                request.license = license_obj  # type: ignore[attr-defined]
            except Exception:
                logger.exception("Failed to refresh license status for org %s", user.organization_id)

        return self.get_response(request)
