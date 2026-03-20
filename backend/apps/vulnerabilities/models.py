"""
Models for the vulnerabilities app.
Defines the Vulnerability model with CVSS/EPSS scoring, deduplication,
diff/timeline logic, and ScanImport tracking.
"""

from __future__ import annotations

from django.db import models
from django.utils import timezone


class ScanImport(models.Model):
    """
    Tracks a single file imported from a scanner into a SubProject.
    The actual parsing is performed asynchronously via a Celery task.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"

    class Tool(models.TextChoices):
        NMAP = "nmap", "Nmap"
        NIKTO = "nikto", "Nikto"
        BURP = "burp", "Burp Suite"
        ZAP = "zap", "OWASP ZAP"
        METASPLOIT = "metasploit", "Metasploit"
        CSV = "csv", "Generic CSV"
        OPENVAS = "openvas", "OpenVAS / Greenbone"
        NESSUS = "nessus", "Nessus"
        UNKNOWN = "unknown", "Unknown"

    subproject = models.ForeignKey(
        "projects.SubProject",
        on_delete=models.CASCADE,
        related_name="scan_imports",
    )
    tool = models.CharField(max_length=32, choices=Tool.choices, default=Tool.UNKNOWN)
    file = models.FileField(upload_to="imports/quarantine/")
    original_filename = models.CharField(max_length=255)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    error_message = models.TextField(blank=True)
    vulnerability_count = models.PositiveIntegerField(default=0)

    imported_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        related_name="scan_imports",
    )
    imported_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        verbose_name = "Scan Import"
        verbose_name_plural = "Scan Imports"
        ordering = ["-imported_at"]

    def __str__(self) -> str:
        return f"{self.tool} / {self.original_filename} ({self.status})"

    def mark_done(self, vuln_count: int) -> None:
        """Mark import as successfully processed."""
        self.status = self.Status.DONE
        self.vulnerability_count = vuln_count
        self.processed_at = timezone.now()
        self.save(update_fields=["status", "vulnerability_count", "processed_at"])

    def mark_failed(self, error: str) -> None:
        """Mark import as failed with an error message."""
        self.status = self.Status.FAILED
        self.error_message = error
        self.processed_at = timezone.now()
        self.save(update_fields=["status", "error_message", "processed_at"])


class Vulnerability(models.Model):
    """
    A single normalized vulnerability finding within a SubProject.
    Supports CVSS/EPSS scoring, deduplication tracking, and lifecycle status.
    """

    class RiskLevel(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Informational"

    class VulnStatus(models.TextChoices):
        OPEN = "open", "Open"
        FIXED = "fixed", "Fixed"
        ACCEPTED = "accepted", "Risk Accepted"
        RETEST = "retest", "Needs Retest"

    subproject = models.ForeignKey(
        "projects.SubProject",
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    scan_import = models.ForeignKey(
        ScanImport,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="vulnerabilities",
    )

    # Core fields
    title = models.CharField(max_length=512)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)

    # Target info
    affected_host = models.CharField(max_length=255, blank=True)
    affected_port = models.CharField(max_length=16, blank=True)
    affected_service = models.CharField(max_length=128, blank=True)

    # CVE / CVSS
    cve_id = models.CharField(max_length=32, blank=True, db_index=True)
    cvss_score = models.FloatField(null=True, blank=True)
    cvss_vector = models.CharField(max_length=255, blank=True)

    # EPSS
    epss_score = models.FloatField(null=True, blank=True, help_text="Exploit Prediction Scoring System (0-1)")

    # Risk
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.MEDIUM)
    risk_score = models.FloatField(
        null=True,
        blank=True,
        help_text="Composite score: f(cvss, epss, exposure_factor)",
    )

    # Status
    vuln_status = models.CharField(max_length=16, choices=VulnStatus.choices, default=VulnStatus.OPEN)

    # Deduplication
    sources = models.JSONField(
        default=list,
        help_text="Tools that identified this vulnerability (after dedup)",
    )
    raw_outputs = models.JSONField(
        default=list,
        help_text="List of raw tool outputs (before normalization)",
    )

    # Diff / timeline
    is_recurring = models.BooleanField(
        default=False,
        help_text="True if this vulnerability was also present in the previous SubProject",
    )

    # Evidence
    evidence_code = models.TextField(blank=True, help_text="Raw output / code snippet as evidence")

    # Screenshots are linked via Screenshot.vulnerability_ref
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Vulnerability"
        verbose_name_plural = "Vulnerabilities"
        ordering = ["-risk_score", "-cvss_score", "title"]
        indexes = [
            models.Index(fields=["subproject", "title", "affected_host", "affected_port"]),
            models.Index(fields=["vuln_status"]),
            models.Index(fields=["risk_level"]),
        ]

    def __str__(self) -> str:
        return f"[{self.risk_level.upper()}] {self.title} @ {self.affected_host}"

    @property
    def dedup_key(self) -> tuple[str, str, str]:
        """Uniqueness key for deduplication within a subproject."""
        return (
            self.title.lower().strip(),
            self.affected_host.lower().strip(),
            self.affected_port.strip(),
        )

    def compute_risk_score(self) -> float:
        """
        Composite risk score: f(cvss_score, epss_score, exposure_factor).
        Returns a value in [0, 10].
        """
        cvss = self.cvss_score or 0.0
        epss = self.epss_score or 0.0
        # Weights: CVSS 70%, EPSS 30%
        score = (cvss * 0.7) + (epss * 10 * 0.3)
        return round(min(score, 10.0), 2)

    def save(self, *args, **kwargs) -> None:
        # Auto-compute risk score before saving
        if self.cvss_score is not None or self.epss_score is not None:
            self.risk_score = self.compute_risk_score()
        super().save(*args, **kwargs)
