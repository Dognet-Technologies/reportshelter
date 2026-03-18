"""
Celery tasks for asynchronous scanner file parsing and NVD enrichment.
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
      8. Schedule NVD enrichment for any CVEs found.

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

    # Schedule NVD enrichment for saved vulnerabilities that have CVE IDs
    vuln_ids_with_cve = [
        v.pk for v in saved if v.cve_id
    ]
    if vuln_ids_with_cve:
        enrich_vulnerabilities_with_nvd.delay(vuln_ids_with_cve)
        logger.info(
            "Scheduled NVD enrichment for %d vulnerabilities.",
            len(vuln_ids_with_cve),
        )

    return {
        "scan_import_id": scan_import_id,
        "tool": scan_import.tool,
        "filename": scan_import.original_filename,
        "vulnerability_count": len(saved),
        "nvd_enrichment_scheduled": len(vuln_ids_with_cve),
    }


@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def enrich_vulnerabilities_with_nvd(self, vulnerability_ids: list[int]) -> dict:
    """
    Enrich a list of Vulnerability records with CVSS data from NVD API v2.

    For each unique CVE ID found among the given vulnerabilities:
      - Fetch CVE data from NVD using nvdlib
      - Update cvss_score and cvss_vector on matching DB records

    Rate limit: 5 req/30s without API key (6s delay), 50 req/30s with key (0.6s delay).
    NVD_API_KEY can be set in .env for higher throughput.
    """
    import os
    import time

    try:
        import nvdlib
    except ImportError:
        logger.warning("nvdlib not installed — skipping NVD enrichment. "
                       "Install with: pip install nvdlib>=0.7.6")
        return {"skipped": True, "reason": "nvdlib not installed"}

    from apps.vulnerabilities.models import Vulnerability

    vulns = list(Vulnerability.objects.filter(pk__in=vulnerability_ids, cve_id__gt=""))
    if not vulns:
        return {"enriched": 0}

    api_key = os.environ.get("NVD_API_KEY", "")
    delay = 0.6 if api_key else 6.0

    # Collect unique CVE IDs
    unique_cves: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        # cve_id may be comma-separated list
        for cve in [c.strip() for c in v.cve_id.split(",") if c.strip()]:
            unique_cves.setdefault(cve, []).append(v)

    enriched_count = 0
    failed_cves: list[str] = []

    for cve_id, cve_vulns in unique_cves.items():
        try:
            kwargs = {"cveId": cve_id, "key": api_key} if api_key else {"cveId": cve_id}
            results = list(nvdlib.searchCVE(**kwargs))

            if not results:
                logger.debug("NVD: no data for %s", cve_id)
                continue

            cve_obj = results[0]

            # Extract best available CVSS score (prefer v3.1 > v3.0 > v2)
            cvss_score: float | None = None
            cvss_vector: str = ""

            metrics = getattr(cve_obj, "metrics", None)
            if metrics:
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = getattr(metrics, metric_key, [])
                    if metric_list:
                        m = metric_list[0]
                        cvss_data = getattr(m, "cvssData", None)
                        if cvss_data:
                            cvss_score = getattr(cvss_data, "baseScore", None)
                            cvss_vector = getattr(cvss_data, "vectorString", "") or ""
                        if cvss_score is not None:
                            break

            if cvss_score is None:
                logger.debug("NVD: no CVSS data for %s", cve_id)
                continue

            # Update all DB vulnerabilities that reference this CVE
            to_update: list[Vulnerability] = []
            for v in cve_vulns:
                if v.cvss_score is None:
                    v.cvss_score = float(cvss_score)
                    v.cvss_vector = cvss_vector
                    to_update.append(v)

            if to_update:
                Vulnerability.objects.bulk_update(to_update, ["cvss_score", "cvss_vector", "risk_score"])
                enriched_count += len(to_update)
                logger.info("NVD enriched %d records for %s (CVSS %.1f)", len(to_update), cve_id, cvss_score)

        except Exception as exc:
            failed_cves.append(cve_id)
            logger.warning("NVD enrichment failed for %s: %s", cve_id, exc)

        # Rate limit
        time.sleep(delay)

    result = {
        "enriched": enriched_count,
        "cves_processed": len(unique_cves),
        "failed": failed_cves,
    }
    logger.info("NVD enrichment complete: %s", result)
    return result


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
