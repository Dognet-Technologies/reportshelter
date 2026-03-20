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
    Enrich Vulnerability records with CVSS (NVD) and EPSS (First.org) data.

    Steps:
      1. Fetch CVSS score + vector from NVD API v2 (via nvdlib) for each unique CVE.
      2. Fetch EPSS scores from First.org EPSS API in bulk (up to 100 CVEs/request).
      3. Persist all updates via bulk_update.

    Rate limits:
      NVD: 5 req/30s without API key (6 s delay), 50 req/30s with key (0.6 s delay).
      EPSS: public API, no key required, batched up to 100 CVEs per call.
    """
    import os
    import time

    try:
        import nvdlib
    except ImportError:
        logger.warning("nvdlib not installed — skipping NVD enrichment.")
        return {"skipped": True, "reason": "nvdlib not installed"}

    from apps.vulnerabilities.models import Vulnerability

    vulns = list(Vulnerability.objects.filter(pk__in=vulnerability_ids, cve_id__gt=""))
    if not vulns:
        return {"enriched": 0}

    api_key = os.environ.get("NVD_API_KEY", "")
    nvd_delay = 0.6 if api_key else 6.0

    # Build map: cve_id → [Vulnerability, ...]
    unique_cves: dict[str, list[Vulnerability]] = {}
    for v in vulns:
        for cve in [c.strip() for c in v.cve_id.split(",") if c.strip()]:
            unique_cves.setdefault(cve, []).append(v)

    # ── Step 1: CVSS from NVD ──────────────────────────────────────────────────
    cvss_map: dict[str, tuple[float, str]] = {}   # cve_id → (score, vector)
    failed_cves: list[str] = []

    for cve_id in unique_cves:
        try:
            kwargs = {"cveId": cve_id, "key": api_key} if api_key else {"cveId": cve_id}
            results = list(nvdlib.searchCVE(**kwargs))
            if not results:
                logger.debug("NVD: no data for %s", cve_id)
                time.sleep(nvd_delay)
                continue

            cve_obj = results[0]
            cvss_score: float | None = None
            cvss_vector: str = ""

            metrics = getattr(cve_obj, "metrics", None)
            if metrics:
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = getattr(metrics, metric_key, [])
                    if metric_list:
                        cvss_data = getattr(metric_list[0], "cvssData", None)
                        if cvss_data:
                            cvss_score = getattr(cvss_data, "baseScore", None)
                            cvss_vector = getattr(cvss_data, "vectorString", "") or ""
                        if cvss_score is not None:
                            break

            if cvss_score is not None:
                cvss_map[cve_id] = (float(cvss_score), cvss_vector)
                logger.debug("NVD: %s → CVSS %.1f", cve_id, cvss_score)

        except Exception as exc:
            failed_cves.append(cve_id)
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)

        time.sleep(nvd_delay)

    # ── Step 2: EPSS from First.org (batch, up to 100 CVEs per request) ───────
    epss_map: dict[str, float] = {}   # cve_id → epss_score (0–1)
    cve_list = list(unique_cves.keys())

    try:
        import urllib.request
        import json as _json

        EPSS_URL = "https://api.first.org/data/1.0/epss"
        BATCH = 100

        for i in range(0, len(cve_list), BATCH):
            batch = cve_list[i : i + BATCH]
            params = "&".join(f"cve={c}" for c in batch)
            url = f"{EPSS_URL}?{params}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "CyberReportPro/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    payload = _json.loads(resp.read().decode())
                for entry in payload.get("data", []):
                    cve_id = entry.get("cve", "").upper()
                    try:
                        epss_map[cve_id] = float(entry.get("epss", 0))
                    except (TypeError, ValueError):
                        pass
                logger.debug("EPSS: fetched %d scores (batch %d)", len(payload.get("data", [])), i // BATCH + 1)
            except Exception as exc:
                logger.warning("EPSS batch fetch failed (offset %d): %s", i, exc)

    except Exception as exc:
        logger.warning("EPSS enrichment error: %s", exc)

    # ── Step 3: Apply updates ──────────────────────────────────────────────────
    to_update: list[Vulnerability] = []
    enriched_count = 0

    for cve_id, cve_vulns in unique_cves.items():
        cvss_entry = cvss_map.get(cve_id)
        epss_val = epss_map.get(cve_id)

        for v in cve_vulns:
            changed = False
            if cvss_entry and v.cvss_score is None:
                v.cvss_score, v.cvss_vector = cvss_entry
                changed = True
            if epss_val is not None and v.epss_score is None:
                v.epss_score = epss_val
                changed = True
            if changed:
                # Recompute composite risk score
                v.risk_score = v.compute_risk_score()
                to_update.append(v)
                enriched_count += 1

    if to_update:
        Vulnerability.objects.bulk_update(
            to_update, ["cvss_score", "cvss_vector", "epss_score", "risk_score"]
        )

    result = {
        "enriched": enriched_count,
        "cves_processed": len(unique_cves),
        "cvss_found": len(cvss_map),
        "epss_found": len(epss_map),
        "failed": failed_cves,
    }
    logger.info("NVD+EPSS enrichment complete: %s", result)
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
