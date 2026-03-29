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
    b"ck_f2cb", b"7b2eec", b"c3295a",
    b"eede99", b"2d70ef", b"b432d3463a02",
)
_S: tuple[bytes, ...] = (
    b"cs_c79", b"193c8b", b"1567bc",
    b"4b09ef", b"13fe62", b"ba8f574cdff9b",
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
    activation_token: str = ""     # opaque token returned by /activate — used for validate/deactivate


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
        # Use the env var if set, otherwise fall back to the embedded default URL.
        self._api_url = os.environ.get("WP_LICENSE_API_URL", _assemble(_U)).rstrip("/")
        # Application-level credentials — embedded, not customer-supplied.
        self._api_key    = _assemble(_K)
        self._api_secret = _assemble(_S)

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

        Credentials are sent as query parameters (consumer_key / consumer_secret)
        since WordPress/Apache installations often strip the Authorization header.

        Raises:
            WPLicenseClientError: on HTTP error, network failure, or
                                  ``success: false`` in the JSON body.
        """
        url = f"{self._api_url}/{path.lstrip('/')}"
        auth_params: dict = {
            "consumer_key": self._api_key,
            "consumer_secret": self._api_secret,
        }
        if params:
            auth_params.update(params)
        try:
            resp = requests.get(
                url,
                params=auth_params,
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
    def _parse_license(data: dict, expected_key: str, activation_token: str = "") -> LicenseInfo:
        """
        Convert a DLM license object into :class:`LicenseInfo`.

        The DLM API returns snake_case fields (``license_key``, ``expires_at``,
        ``times_activated``, ``activations_limit``) inside a nested ``license``
        sub-object for both the activate and validate routes.

        Also verifies that the returned key matches ``expected_key`` to guard
        against response-substitution attacks.
        """
        returned_key: str = data.get("license_key", "")
        if returned_key and returned_key.upper() != expected_key.upper():
            raise WPLicenseClientError(
                "DLM response license_key mismatch — possible response substitution."
            )

        status_code = data.get("status")
        # Use is_expired field when present for a more reliable active/expired decision.
        if data.get("is_expired") is True:
            status_str = "expired"
        else:
            status_str = _DLM_STATUS_MAP.get(status_code, "unknown")
            if status_str == "expired" and data.get("is_expired") is False:
                status_str = "active"

        return LicenseInfo(
            key=returned_key or expected_key,
            status=status_str,
            expires_at=data.get("expires_at"),
            activations_limit=data.get("activations_limit"),
            activations_count=data.get("times_activated", 0),
            activation_token=activation_token,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def activate_license(self, license_key: str, instance_id: str) -> LicenseInfo:
        """
        Activate *license_key* for *instance_id* (organisation UUID).

        Calls ``GET /licenses/activate/{license_key}?instanceId=…``.

        Returns a :class:`LicenseInfo` that includes the ``activation_token``
        — an opaque string that must be stored and passed to :meth:`validate_license`
        and :meth:`deactivate_license` for all subsequent calls.

        Raises:
            WPLicenseClientError: if the key is invalid, exhausted, or the API returns an error.
        """
        logger.info("Activating key %s for instance %s", license_key[:8], instance_id)
        seg = f"{_SEG[0].decode()}/{_SEG[1].decode()}"
        body = self._get(f"{seg}/{license_key}", params={"instanceId": instance_id})

        activation_data = body["data"]
        token: str = activation_data.get("token", "")
        license_data: dict = activation_data.get("license", {})
        return self._parse_license(license_data, license_key, activation_token=token)

    def validate_license(self, activation_token: str) -> LicenseInfo:
        """
        Confirm that an existing activation is still valid.

        Calls ``GET /licenses/validate/{activation_token}``.

        Args:
            activation_token: the opaque token returned by :meth:`activate_license`.

        Raises:
            WPLicenseClientError: on API/network error or if the token is invalid.
        """
        logger.debug("Validating activation token %s…", activation_token[:8])
        seg = f"{_SEG[0].decode()}/validate"
        body = self._get(f"{seg}/{activation_token}")

        activation_data = body["data"]
        license_data: dict = activation_data.get("license", activation_data)
        key = license_data.get("license_key", "")
        return self._parse_license(license_data, key, activation_token=activation_token)

    def deactivate_license(self, activation_token: str) -> bool:
        """
        Deactivate an existing activation.

        Calls ``GET /licenses/deactivate/{activation_token}``.

        Args:
            activation_token: the opaque token returned by :meth:`activate_license`.

        Returns:
            True if deactivated successfully.

        Raises:
            WPLicenseClientError: on API/network error.
        """
        logger.info("Deactivating activation token %s…", activation_token[:8])
        seg = f"{_SEG[0].decode()}/{_SEG[2].decode()}"
        self._get(f"{seg}/{activation_token}")
        return True
