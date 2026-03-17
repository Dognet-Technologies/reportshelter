"""
Client for the Digital License Manager (DLM) WordPress plugin.

Configurazione richiesta (variabili d'ambiente):
    WP_LICENSE_API_URL=https://your-wordpress-site.com/wp-json/dlm/v1
    WP_LICENSE_API_KEY=<consumer_key>
    WP_LICENSE_API_SECRET=<consumer_secret>

Endpoints utilizzati:
    - GET  /licenses/{license_key}              → validate / get info
    - GET  /licenses/activate/{license_key}     → activate for an instance
    - GET  /licenses/deactivate/{license_key}   → deactivate for an instance

Autenticazione:
    Authorization: Bearer base64(consumer_key:consumer_secret)
"""

import base64
import logging
import os
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# DLM status codes (integers returned by the plugin)
_DLM_STATUS_MAP = {
    1: "inactive",
    2: "active",
    3: "expired",
    4: "disabled",
}


@dataclass
class LicenseInfo:
    """Normalized response from the DLM API."""

    key: str
    status: str          # "active" | "inactive" | "expired" | "disabled"
    expires_at: Optional[str]  # "YYYY-MM-DD HH:MM:SS" or None
    activations_limit: Optional[int]
    activations_count: int


class WPLicenseClientError(Exception):
    """Raised when the DLM API returns an error or an unexpected response."""


class WPLicenseClient:
    """
    HTTP client for the Digital License Manager WordPress plugin.

    Reads configuration from environment variables:
        WP_LICENSE_API_URL    — base URL, e.g. https://dognet.tech/wp-json/dlm/v1
        WP_LICENSE_API_KEY    — consumer key  (ck_…)
        WP_LICENSE_API_SECRET — consumer secret (cs_…)

    Authentication follows the HTTP Basic Auth variant documented by DLM:
        Authorization: Bearer base64(consumer_key:consumer_secret)
    """

    _TIMEOUT = 10  # seconds

    def __init__(self) -> None:
        self._api_url = os.environ.get("WP_LICENSE_API_URL", "").rstrip("/")
        self._api_key = os.environ.get("WP_LICENSE_API_KEY", "")
        self._api_secret = os.environ.get("WP_LICENSE_API_SECRET", "")
        self._configured = bool(self._api_url and self._api_key and self._api_secret)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _auth_header(self) -> dict:
        """Return the Authorization header expected by DLM."""
        token = base64.b64encode(
            f"{self._api_key}:{self._api_secret}".encode()
        ).decode()
        return {"Authorization": f"Bearer {token}"}

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """
        Perform a GET request against the DLM API.

        Args:
            path:   URL path relative to the API base URL.
            params: Optional query string parameters.

        Returns:
            The parsed JSON response body as a dict.

        Raises:
            WPLicenseClientError: On HTTP errors or unexpected response format.
        """
        url = f"{self._api_url}/{path.lstrip('/')}"
        try:
            response = requests.get(
                url,
                headers=self._auth_header,
                params=params,
                timeout=self._TIMEOUT,
            )
        except requests.RequestException as exc:
            raise WPLicenseClientError(f"Network error contacting DLM API: {exc}") from exc

        if not response.ok:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            raise WPLicenseClientError(
                f"DLM API returned HTTP {response.status_code}: {detail}"
            )

        try:
            body = response.json()
        except Exception as exc:
            raise WPLicenseClientError(f"Invalid JSON from DLM API: {exc}") from exc

        if not body.get("success"):
            raise WPLicenseClientError(
                f"DLM API responded with success=false: {body.get('message', body)}"
            )

        return body

    @staticmethod
    def _parse_license_info(data: dict) -> LicenseInfo:
        """
        Convert a DLM API ``data`` object to a :class:`LicenseInfo`.

        Args:
            data: The ``data`` dict from the DLM JSON response.

        Returns:
            A populated :class:`LicenseInfo` instance.
        """
        status_code = data.get("status")
        status_str = _DLM_STATUS_MAP.get(status_code, "unknown")

        return LicenseInfo(
            key=data.get("licenseKey", ""),
            status=status_str,
            expires_at=data.get("expiresAt"),  # "YYYY-MM-DD HH:MM:SS" or None
            activations_limit=data.get("activationsLimit"),
            activations_count=data.get("timesActivated", 0),
        )

    def _require_configured(self) -> None:
        """Raise :exc:`NotImplementedError` if env vars are missing."""
        if not self._configured:
            raise NotImplementedError(
                "Configure WP_LICENSE_API_URL, WP_LICENSE_API_KEY, and WP_LICENSE_API_SECRET "
                "to enable DLM license management."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_license(self, license_key: str) -> LicenseInfo:
        """
        Retrieve current status and metadata for a license key.

        Calls ``GET /licenses/{license_key}``.

        Args:
            license_key: The license key to validate (e.g. ``RS-XXXX-XXXX-XXXX-XXXX``).

        Returns:
            :class:`LicenseInfo` with current status and expiry.

        Raises:
            WPLicenseClientError: If the API call fails or returns an error.
            NotImplementedError: If env vars are not configured.
        """
        self._require_configured()
        logger.debug("Validating license key %s…", license_key[:8])
        body = self._get(f"licenses/{license_key}")
        return self._parse_license_info(body["data"])

    def activate_license(self, license_key: str, instance_id: str) -> LicenseInfo:
        """
        Activate a license key for a specific installation instance.

        Calls ``GET /licenses/activate/{license_key}`` with ``instanceId`` as
        a query parameter so the activation is tied to this organisation.

        Args:
            license_key: The license key to activate.
            instance_id: Unique identifier for this installation (organisation UUID).

        Returns:
            :class:`LicenseInfo` with updated activation count and expiry.

        Raises:
            WPLicenseClientError: If the API call fails or the key is invalid/expired.
            NotImplementedError: If env vars are not configured.
        """
        self._require_configured()
        logger.info("Activating license key %s for instance %s", license_key[:8], instance_id)
        body = self._get(
            f"licenses/activate/{license_key}",
            params={"instanceId": instance_id},
        )
        return self._parse_license_info(body["data"])

    def deactivate_license(self, license_key: str, instance_id: str) -> bool:
        """
        Deactivate a license key for a specific installation instance.

        Calls ``GET /licenses/deactivate/{license_key}`` with ``instanceId``
        as a query parameter.

        Args:
            license_key: The license key to deactivate.
            instance_id: The instance ID previously used during activation.

        Returns:
            ``True`` if deactivated successfully.

        Raises:
            WPLicenseClientError: If the API call fails.
            NotImplementedError: If env vars are not configured.
        """
        self._require_configured()
        logger.info("Deactivating license key %s for instance %s", license_key[:8], instance_id)
        self._get(
            f"licenses/deactivate/{license_key}",
            params={"instanceId": instance_id},
        )
        return True
