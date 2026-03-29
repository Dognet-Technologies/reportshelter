"""
Models for the reports app.
Tracks generated report exports per SubProject.
"""

from django.conf import settings
from django.db import models


class ReportExport(models.Model):
    """
    A generated report export (PDF, HTML, or XML) for a SubProject.
    """

    class Format(models.TextChoices):
        PDF = "pdf", "PDF"
        HTML = "html", "HTML"
        XML = "xml", "XML"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        GENERATING = "generating", "Generating"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"

    subproject = models.ForeignKey(
        "projects.SubProject",
        on_delete=models.CASCADE,
        related_name="report_exports",
    )
    format = models.CharField(max_length=8, choices=Format.choices, default=Format.PDF)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    file = models.FileField(upload_to="reports/exports/", blank=True, null=True)
    error_message = models.TextField(blank=True)

    # Options snapshot at generation time
    options = models.JSONField(
        default=dict,
        help_text="Serialized report options (filters, template, etc.) used for this export.",
    )
    report_name = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="Human-readable name set at generation time.",
    )

    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="report_exports",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Report Export"
        verbose_name_plural = "Report Exports"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Report({self.format}) for {self.subproject} [{self.status}]"
