"""
Celery tasks for asynchronous report generation.
"""

from __future__ import annotations

import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def generate_report(self, export_id: int) -> dict:
    """
    Asynchronously generate a report export (PDF/HTML/XML).

    Args:
        export_id: PK of a ReportExport instance.

    Returns:
        Dict with export summary on success.
    """
    from .generator import ReportGenerator
    from .models import ReportExport

    try:
        export = ReportExport.objects.get(pk=export_id)
    except ReportExport.DoesNotExist:
        logger.error("ReportExport %s not found.", export_id)
        return {"error": "ReportExport not found."}

    try:
        gen = ReportGenerator(export_id)
        gen.generate()
        logger.info("Report %s generated successfully.", export_id)
        return {
            "export_id": export_id,
            "format": export.format,
            "status": "done",
        }
    except Exception as exc:
        logger.exception("Report generation failed for export %s.", export_id)
        try:
            self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {"error": str(exc), "status": "failed"}
