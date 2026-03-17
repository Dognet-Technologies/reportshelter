"""
Views for the licensing app.
"""

import logging

from rest_framework import permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import AuditLog
from apps.accounts.permissions import IsOrgAdmin

from .models import License, LicenseStatus, SALES_CONTACT
from .serializers import ActivateLicenseSerializer, LicenseSerializer
from .wp_license_client import WPLicenseClient, WPLicenseClientError

logger = logging.getLogger(__name__)

_EXPIRED_MSG = (
    "Your license has expired. "
    f"Contact {SALES_CONTACT} to purchase or renew."
)
_NOT_CONFIGURED_MSG = (
    "License activation service is not reachable. "
    f"Contact {SALES_CONTACT} for assistance."
)


class LicenseStatusView(APIView):
    """
    GET /licensing/status/
    Returns current license status for the authenticated user's organization.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request: Request) -> Response:
        try:
            license_obj = request.user.organization.license
            license_obj.refresh_status()
        except License.DoesNotExist:
            return Response(
                {"success": False, "error": "No license found for your organization."},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(LicenseSerializer(license_obj).data)


class ActivateLicenseView(APIView):
    """
    POST /licensing/activate/
    Activate a PRO license key via the DLM server.
    Only org admins can activate.
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        serializer = ActivateLicenseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        license_key: str = serializer.validated_data["license_key"]
        org = request.user.organization
        instance_id = str(org.id)

        client = WPLicenseClient()
        if not client._configured:
            return Response(
                {"success": False, "error": _NOT_CONFIGURED_MSG},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        try:
            license_info = client.activate_license(license_key, instance_id)
        except WPLicenseClientError as exc:
            logger.warning("License activation failed for org %s: %s", org.id, exc)
            return Response(
                {"success": False, "error": f"License activation failed: {exc}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.utils.dateparse import parse_datetime
        expires_at = parse_datetime(license_info.expires_at) if license_info.expires_at else None

        try:
            license_obj = org.license
        except License.DoesNotExist:
            license_obj = License(organization=org)

        license_obj.activate_pro(license_key=license_key, expires_at=expires_at)

        AuditLog.log(
            action=AuditLog.Action.LICENSE_ACTIVATED,
            user=request.user,
            detail={"license_key": license_key[:8] + "****"},
        )

        return Response(LicenseSerializer(license_obj).data)


class DeactivateLicenseView(APIView):
    """
    POST /licensing/deactivate/
    Deactivate the current PRO license (org admin only).
    Always requires a successful call to the DLM server — no offline bypass.
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        org = request.user.organization
        try:
            license_obj = org.license
        except License.DoesNotExist:
            return Response(
                {"success": False, "error": "No license found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if license_obj.status != LicenseStatus.PRO_ACTIVE:
            return Response(
                {"success": False, "error": "No active PRO license to deactivate."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = WPLicenseClient()
        if not client._configured:
            return Response(
                {"success": False, "error": _NOT_CONFIGURED_MSG},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        instance_id = str(org.id)
        try:
            client.deactivate_license(license_obj.license_key, instance_id)
        except WPLicenseClientError as exc:
            logger.warning("Remote deactivation failed for org %s: %s", org.id, exc)
            return Response(
                {
                    "success": False,
                    "error": (
                        f"Could not deactivate license on the server: {exc}. "
                        f"Contact {SALES_CONTACT} if the problem persists."
                    ),
                },
                status=status.HTTP_502_BAD_GATEWAY,
            )

        license_obj.invalidate()

        AuditLog.log(
            action=AuditLog.Action.LICENSE_ACTIVATED,
            user=request.user,
            detail={"action": "deactivated", "license_key": license_obj.license_key[:8] + "****"},
        )

        return Response({"success": True, "message": "License deactivated."})
