"""
HTTP client for the Digital License Manager (DLM) WordPress plugin.

Authentication (HTTP Basic Auth variant documented by DLM):
    Authorization: Bearer base64(consumer_key:consumer_secret)

Endpoints used:
    GET /licenses/{key}              — validate / get info
    GET /licenses/activate/{key}     — activate for an instance
    GET /licenses/deactivate/{key}   — deactivate for an instance

The API URL is read from WP_LICENSE_API_URL (env) with a built-in default.
Application credentials (consumer key / secret) are embedded — they are
NOT customer-configurable and must not appear in the customer's .env.
"""

import base64
import logging
import os
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# DLM integer status codes → normalised strings
_DLM_STATUS_MAP: dict[int, str] = {
    1: "inactive",
    2: "active",
    3: "expired",
    4: "disabled",
}

# API base path segments — assembled at call time to avoid a single
# plaintext string that trivially reveals the full endpoint structure.
_SEG: tuple[bytes, ...] = (
    b"licenses",
    b"activate",
    b"deactivate",
)

# Application credentials (owner-side — not customer-configurable).
# Split into byte fragments to avoid trivial grep/string extraction.
_K: tuple[bytes, ...] = (
    b"ck_191d", b"e0ac583", b"4b9adb4",
    b"3b7523e", b"eaafbf6", b"a35c789c",
)
_S: tuple[bytes, ...] = (
    b"cs_ce1b", b"8f824c6", b"c2e2a04",
    b"3b3356a", b"c95b125", b"3703a1b5",
)
_U: tuple[bytes, ...] = (
    b"https://dognet", b".tech/wp-json",
    b"/dlm/v1",
)


def _assemble(parts: tuple[bytes, ...]) -> str:
    """Join byte fragments into a plain string."""
    return b"".join(parts).decode()


@dataclass
class LicenseInfo:
    """Normalised response from a DLM API call."""

    key: str
    status: str                    # "active" | "inactive" | "expired" | "disabled"
    expires_at: Optional[str]      # "YYYY-MM-DD HH:MM:SS" or None
    activations_limit: Optional[int]
    activations_count: int


class WPLicenseClientError(Exception):
    """Raised when the DLM API returns an error or an unexpected response."""


class WPLicenseClient:
    """
    HTTP client for the Digital License Manager WordPress plugin.

    The API URL can be overridden via WP_LICENSE_API_URL for development.
    Application credentials are embedded and cannot be overridden via env.
    """

    _TIMEOUT = 10  # seconds

    def __init__(self) -> None:
        self._api_url = os.environ.get(
            "WP_LICENSE_API_URL", _assemble(_U)
        ).rstrip("/")
        # Application-level credentials — embedded, not customer-supplied.
        self._api_key    = _assemble(_K)
        self._api_secret = _assemble(_S)
        self._configured = bool(self._api_url and self._api_key and self._api_secret)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _auth_header(self) -> dict[str, str]:
        """Return Authorization header: Bearer base64(key:secret)."""
        token = base64.b64encode(
            f"{self._api_key}:{self._api_secret}".encode()
        ).decode()
        return {"Authorization": f"Bearer {token}"}

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """
        Perform an authenticated GET against the DLM API.

        Raises:
            WPLicenseClientError: on HTTP error, network failure, or
                                  ``success: false`` in the JSON body.
        """
        url = f"{self._api_url}/{path.lstrip('/')}"
        try:
            resp = requests.get(
                url,
                headers=self._auth_header,
                params=params,
                timeout=self._TIMEOUT,
            )
        except requests.RequestException as exc:
            raise WPLicenseClientError(
                f"Network error contacting DLM API: {exc}"
            ) from exc

        if not resp.ok:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise WPLicenseClientError(
                f"DLM API returned HTTP {resp.status_code}: {detail}"
            )

        try:
            body = resp.json()
        except Exception as exc:
            raise WPLicenseClientError(
                f"Invalid JSON from DLM API: {exc}"
            ) from exc

        if not body.get("success"):
            raise WPLicenseClientError(
                f"DLM API responded with success=false: {body.get('message', body)}"
            )

        return body

    @staticmethod
    def _parse(data: dict, expected_key: str) -> LicenseInfo:
        """
        Convert a DLM ``data`` object into :class:`LicenseInfo`.

        Also verifies that the returned ``licenseKey`` matches ``expected_key``
        to guard against response-substitution.
        """
        returned_key: str = data.get("licenseKey", "")
        if returned_key and returned_key.upper() != expected_key.upper():
            raise WPLicenseClientError(
                "DLM response licenseKey mismatch — possible response substitution."
            )

        status_code = data.get("status")
        status_str  = _DLM_STATUS_MAP.get(status_code, "unknown")

        return LicenseInfo(
            key=returned_key or expected_key,
            status=status_str,
            expires_at=data.get("expiresAt"),
            activations_limit=data.get("activationsLimit"),
            activations_count=data.get("timesActivated", 0),
        )

    def _require_configured(self) -> None:
        if not self._configured:
            raise NotImplementedError(
                "WP_LICENSE_API_URL is not set."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_license(self, license_key: str) -> LicenseInfo:
        """
        Retrieve current status and metadata for *license_key*.

        Calls ``GET /licenses/{license_key}``.

        Raises:
            WPLicenseClientError: on API/network error.
            NotImplementedError:  if API URL is not configured.
        """
        self._require_configured()
        logger.debug("Validating key %s…", license_key[:8])
        seg = _SEG[0].decode()
        body = self._get(f"{seg}/{license_key}")
        return self._parse(body["data"], license_key)

    def activate_license(self, license_key: str, instance_id: str) -> LicenseInfo:
        """
        Activate *license_key* for *instance_id* (organisation UUID).

        Calls ``GET /licenses/activate/{license_key}?instanceId=…``.

        Raises:
            WPLicenseClientError: if the key is invalid, exhausted, or the
                                  API returns an error.
            NotImplementedError:  if API URL is not configured.
        """
        self._require_configured()
        logger.info("Activating key %s for instance %s", license_key[:8], instance_id)
        seg = f"{_SEG[0].decode()}/{_SEG[1].decode()}"
        body = self._get(f"{seg}/{license_key}", params={"instanceId": instance_id})
        return self._parse(body["data"], license_key)

    def deactivate_license(self, license_key: str, instance_id: str) -> bool:
        """
        Deactivate *license_key* for *instance_id*.

        Calls ``GET /licenses/deactivate/{license_key}?instanceId=…``.

        Returns:
            True if deactivated successfully.

        Raises:
            WPLicenseClientError: on API/network error.
            NotImplementedError:  if API URL is not configured.
        """
        self._require_configured()
        logger.info("Deactivating key %s for instance %s", license_key[:8], instance_id)
        seg = f"{_SEG[0].decode()}/{_SEG[2].decode()}"
        self._get(f"{seg}/{license_key}", params={"instanceId": instance_id})
        return True
