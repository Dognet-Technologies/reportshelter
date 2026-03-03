"""
Celery tasks for asynchronous scanner file parsing.
"""

from __future__ import annotations

import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def parse_scan_file(self, scan_import_id: int) -> dict:
    """
    Asynchronously parse an uploaded scanner file.

    Steps:
      1. Load the ScanImport record.
      2. Set status to PROCESSING.
      3. Select the appropriate parser based on `tool`.
      4. Parse the file → List[NormalizedVulnerability].
      5. Deduplicate and persist vulnerabilities.
      6. Update ScanImport status to DONE or FAILED.
      7. Notify connected WebSocket clients via channels.

    Returns a dict with parsing summary.
    """
    from apps.vulnerabilities.deduplication import deduplicate_and_save
    from apps.vulnerabilities.models import ScanImport

    from .registry import get_parser

    try:
        scan_import = ScanImport.objects.select_related("subproject__project").get(pk=scan_import_id)
    except ScanImport.DoesNotExist:
        logger.error("ScanImport %s not found.", scan_import_id)
        return {"error": "ScanImport not found."}

    scan_import.status = ScanImport.Status.PROCESSING
    scan_import.save(update_fields=["status"])

    try:
        parser = get_parser(scan_import.tool)
    except ValueError as exc:
        scan_import.mark_failed(str(exc))
        return {"error": str(exc)}

    try:
        with scan_import.file.open("rb") as f:
            normalized_vulns, error = parser.safe_parse(f)
    except Exception as exc:
        error_msg = f"Failed to open file: {exc}"
        logger.exception(error_msg)
        scan_import.mark_failed(error_msg)
        return {"error": error_msg}

    if error:
        scan_import.mark_failed(error)
        return {"error": error}

    # Persist with deduplication
    saved = deduplicate_and_save(
        normalized_vulns=normalized_vulns,
        subproject_id=scan_import.subproject_id,
        scan_import_id=scan_import_id,
    )

    scan_import.mark_done(len(saved))

    logger.info(
        "ScanImport %s: parsed %d vulnerabilities from %s.",
        scan_import_id,
        len(saved),
        scan_import.original_filename,
    )

    # Notify WebSocket clients
    try:
        _notify_import_complete(scan_import, len(saved))
    except Exception as exc:
        logger.warning("WebSocket notification failed: %s", exc)

    return {
        "scan_import_id": scan_import_id,
        "tool": scan_import.tool,
        "filename": scan_import.original_filename,
        "vulnerability_count": len(saved),
    }


def _notify_import_complete(scan_import, vuln_count: int) -> None:
    """Send a WebSocket notification to the project group on import completion."""
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    project_id = scan_import.subproject.project_id
    channel_layer = get_channel_layer()

    async_to_sync(channel_layer.group_send)(
        f"project_lock_{project_id}",
        {
            "type": "import.complete",
            "scan_import_id": scan_import.pk,
            "tool": scan_import.tool,
            "filename": scan_import.original_filename,
            "vulnerability_count": vuln_count,
        },
    )
