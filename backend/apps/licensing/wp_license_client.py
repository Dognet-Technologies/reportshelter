"""
Placeholder for integration with the WordPress License Manager Plugin.

Configurazione richiesta (variabili d'ambiente):
    WP_LICENSE_API_URL=https://your-wordpress-site.com/wp-json/lmfwc/v2
    WP_LICENSE_API_KEY=<consumer_key>
    WP_LICENSE_API_SECRET=<consumer_secret>

Quando implementata, ogni metodo chiama le API REST del plugin:
    - POST  /licenses/activate
    - GET   /licenses/{key}
    - POST  /licenses/deactivate
"""

import logging
import os
from dataclasses import dataclass
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)


@dataclass
class LicenseInfo:
    """Normalized response from the WP License Manager API."""

    key: str
    status: str          # e.g. "active", "inactive", "expired"
    expires_at: Optional[str]  # ISO-8601 string or None
    activations_limit: Optional[int]
    activations_count: int


class WPLicenseClientError(Exception):
    """Raised when the WP License Manager API returns an error."""


class WPLicenseClient:
    """
    Placeholder for integration with WordPress License Manager Plugin.

    Configurazione richiesta (variabili d'ambiente):
        WP_LICENSE_API_URL=https://your-wordpress-site.com/wp-json/lmfwc/v2
        WP_LICENSE_API_KEY=<consumer_key>
        WP_LICENSE_API_SECRET=<consumer_secret>

    Metodi da implementare con le API reali del plugin:
        - activate_license(license_key, instance_id) -> LicenseInfo
        - validate_license(license_key) -> LicenseInfo
        - deactivate_license(license_key, instance_id) -> bool
    """

    def __init__(self) -> None:
        self._api_url = os.environ.get("WP_LICENSE_API_URL", "")
        self._api_key = os.environ.get("WP_LICENSE_API_KEY", "")
        self._api_secret = os.environ.get("WP_LICENSE_API_SECRET", "")
        self._configured = bool(self._api_url and self._api_key and self._api_secret)

    @property
    def _auth(self) -> HTTPBasicAuth:
        return HTTPBasicAuth(self._api_key, self._api_secret)

    def activate_license(self, license_key: str, instance_id: str) -> LicenseInfo:
        """
        Activate a license key for a specific instance.

        TODO: Implement by calling:
            POST {WP_LICENSE_API_URL}/licenses/activate
            Body: { "licenseKey": license_key, "instanceId": instance_id }

        Args:
            license_key: The license key to activate.
            instance_id: Unique identifier for this installation (e.g., organization UUID).

        Returns:
            LicenseInfo with current status and expiry.

        Raises:
            WPLicenseClientError: If the API call fails or key is invalid.
            NotImplementedError: If WP_LICENSE_API_URL is not configured.
        """
        if not self._configured:
            raise NotImplementedError(
                "Configure WP_LICENSE_API_URL, WP_LICENSE_API_KEY, WP_LICENSE_API_SECRET "
                "to enable license activation."
            )
        # TODO: implement real API call
        raise NotImplementedError("activate_license not yet implemented — configure WP License Manager API.")

    def validate_license(self, license_key: str) -> LicenseInfo:
        """
        Validate that a license key is still active and retrieve its info.

        TODO: Implement by calling:
            GET {WP_LICENSE_API_URL}/licenses/{license_key}

        Args:
            license_key: The license key to validate.

        Returns:
            LicenseInfo with current status and expiry.

        Raises:
            WPLicenseClientError: If the API call fails.
            NotImplementedError: If WP_LICENSE_API_URL is not configured.
        """
        if not self._configured:
            raise NotImplementedError(
                "Configure WP_LICENSE_API_URL, WP_LICENSE_API_KEY, WP_LICENSE_API_SECRET "
                "to enable license validation."
            )
        # TODO: implement real API call
        raise NotImplementedError("validate_license not yet implemented — configure WP License Manager API.")

    def deactivate_license(self, license_key: str, instance_id: str) -> bool:
        """
        Deactivate a license key for a specific instance.

        TODO: Implement by calling:
            POST {WP_LICENSE_API_URL}/licenses/deactivate
            Body: { "licenseKey": license_key, "instanceId": instance_id }

        Args:
            license_key: The license key to deactivate.
            instance_id: The instance ID previously used during activation.

        Returns:
            True if deactivated successfully.

        Raises:
            WPLicenseClientError: If the API call fails.
            NotImplementedError: If WP_LICENSE_API_URL is not configured.
        """
        if not self._configured:
            raise NotImplementedError(
                "Configure WP_LICENSE_API_URL, WP_LICENSE_API_KEY, WP_LICENSE_API_SECRET "
                "to enable license deactivation."
            )
        # TODO: implement real API call
        raise NotImplementedError("deactivate_license not yet implemented — configure WP License Manager API.")
