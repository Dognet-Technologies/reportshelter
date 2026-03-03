"""
Views for the licensing app.
"""

import logging
import uuid

from rest_framework import permissions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import AuditLog
from apps.accounts.permissions import IsOrgAdmin

from .models import License, LicenseStatus
from .serializers import ActivateLicenseSerializer, LicenseSerializer
from .wp_license_client import WPLicenseClient, WPLicenseClientError

logger = logging.getLogger(__name__)


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

        return Response(
            {
                "success": True,
                "license": LicenseSerializer(license_obj).data,
            }
        )


class ActivateLicenseView(APIView):
    """
    POST /licensing/activate/
    Activate a PRO license key via WP License Manager.
    Only org admins can activate.
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        serializer = ActivateLicenseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        license_key = serializer.validated_data["license_key"]
        org = request.user.organization
        # Use org ID as instance identifier for the WP License Manager
        instance_id = str(org.id)

        client = WPLicenseClient()
        try:
            license_info = client.activate_license(license_key, instance_id)
        except NotImplementedError:
            return Response(
                {
                    "success": False,
                    "error": (
                        "License activation is not yet configured. "
                        "Set WP_LICENSE_API_URL, WP_LICENSE_API_KEY, and WP_LICENSE_API_SECRET."
                    ),
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except WPLicenseClientError as e:
            logger.warning("License activation failed for org %s: %s", org.id, e)
            return Response(
                {"success": False, "error": f"License activation failed: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Parse expiry date from API response
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

        return Response(
            {
                "success": True,
                "message": "License activated successfully.",
                "license": LicenseSerializer(license_obj).data,
            }
        )


class DeactivateLicenseView(APIView):
    """
    POST /licensing/deactivate/
    Deactivate the current PRO license (org admin only).
    """

    permission_classes = [permissions.IsAuthenticated, IsOrgAdmin]

    def post(self, request: Request) -> Response:
        org = request.user.organization
        try:
            license_obj = org.license
        except License.DoesNotExist:
            return Response({"success": False, "error": "No license found."}, status=status.HTTP_404_NOT_FOUND)

        if license_obj.status != LicenseStatus.PRO_ACTIVE:
            return Response(
                {"success": False, "error": "No active PRO license to deactivate."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client = WPLicenseClient()
        instance_id = str(org.id)
        try:
            client.deactivate_license(license_obj.license_key, instance_id)
        except NotImplementedError:
            # WP client not configured — still allow local deactivation
            logger.info("WP License client not configured; deactivating locally for org %s", org.id)
        except WPLicenseClientError as e:
            logger.warning("Remote deactivation failed: %s", e)

        license_obj.invalidate()
        return Response({"success": True, "message": "License deactivated."})
