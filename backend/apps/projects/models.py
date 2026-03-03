"""
Models for the projects app.
Defines Project, SubProject, ProjectLock and related models.
"""

from django.conf import settings
from django.db import models
from django.utils import timezone


class Project(models.Model):
    """
    A cybersecurity assessment project belonging to an Organization.
    Contains client info, graphic options, and header/footer config.
    """

    class FontFamily(models.TextChoices):
        INTER = "Inter", "Inter"
        ROBOTO = "Roboto", "Roboto"
        SOURCE_SANS = "Source Sans Pro", "Source Sans Pro"
        OPEN_SANS = "Open Sans", "Open Sans"
        LATO = "Lato", "Lato"

    class PageNumbering(models.TextChoices):
        N_OF_TOTAL = "n_of_total", "N / TOT"
        N_ONLY = "n_only", "N"
        NONE = "none", "None"

    organization = models.ForeignKey(
        "accounts.Organization",
        on_delete=models.CASCADE,
        related_name="projects",
    )

    # Basic info
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    start_date = models.DateField(null=True, blank=True)

    # Client info
    client_name = models.CharField(max_length=255, blank=True)
    client_logo = models.ImageField(upload_to="projects/client_logos/", blank=True, null=True)
    client_contact = models.CharField(max_length=255, blank=True)
    client_email = models.EmailField(blank=True)
    client_phone = models.CharField(max_length=64, blank=True)

    # Graphic options
    primary_color = models.CharField(max_length=7, default="#3b82f6")
    secondary_color = models.CharField(max_length=7, default="#64748b")
    font_family = models.CharField(max_length=64, choices=FontFamily.choices, default=FontFamily.INTER)

    # Watermark
    watermark_text = models.CharField(max_length=128, blank=True)
    watermark_image = models.ImageField(upload_to="projects/watermarks/", blank=True, null=True)
    watermark_opacity = models.FloatField(default=0.15)

    # Header config
    header_logo_left = models.BooleanField(default=True)
    header_text_center = models.CharField(max_length=255, blank=True)
    header_show_date = models.BooleanField(default=True)

    # Footer config
    footer_text = models.TextField(blank=True)
    footer_page_numbering = models.CharField(
        max_length=16,
        choices=PageNumbering.choices,
        default=PageNumbering.N_OF_TOTAL,
    )

    # Report template (predefined key or custom HTML upload path)
    template_name = models.CharField(max_length=64, default="default")
    template_html = models.FileField(upload_to="projects/templates/", blank=True, null=True)

    # Members with access (in addition to org members)
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="accessible_projects",
        blank=True,
        through="ProjectMembership",
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_projects",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Project"
        verbose_name_plural = "Projects"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.title} ({self.organization})"

    def is_accessible_by(self, user: settings.AUTH_USER_MODEL) -> bool:  # type: ignore[valid-type]
        """Return True if the user can access this project."""
        return (
            self.organization_id == user.organization_id
            or self.members.filter(pk=user.pk).exists()
        )


class ProjectMembership(models.Model):
    """
    Through model for Project.members — tracks role within the project.
    """

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="project_memberships")
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("project", "user")]
        verbose_name = "Project Membership"

    def __str__(self) -> str:
        return f"{self.user} → {self.project}"


class SubProject(models.Model):
    """
    A single engagement/scan phase within a Project (e.g. "Q1 2025 Scan", "Retest March 2025").
    Contains imported scan files, vulnerabilities, and screenshots.
    """

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="subprojects")
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    scan_date = models.DateField(null=True, blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_subprojects",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "SubProject"
        verbose_name_plural = "SubProjects"
        ordering = ["scan_date", "created_at"]

    def __str__(self) -> str:
        return f"{self.project.title} / {self.title}"


class ProjectLock(models.Model):
    """
    Concurrency lock for a Project.
    Acquired when a user opens a project in edit mode.
    Auto-expires after TIMEOUT_MINUTES of inactivity.
    """

    TIMEOUT_MINUTES: int = getattr(settings, "PROJECT_LOCK_TIMEOUT_MINUTES", 30)

    project = models.OneToOneField(Project, on_delete=models.CASCADE, related_name="lock")
    locked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="held_locks",
    )
    locked_at = models.DateTimeField(auto_now_add=True)
    last_heartbeat = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = "Project Lock"

    def __str__(self) -> str:
        return f"Lock({self.project_id}) by {self.locked_by}"

    def is_expired(self) -> bool:
        """Return True if the lock has timed out due to inactivity."""
        elapsed = (timezone.now() - self.last_heartbeat).total_seconds()
        return elapsed > self.TIMEOUT_MINUTES * 60

    def refresh(self) -> None:
        """Update the heartbeat timestamp."""
        self.last_heartbeat = timezone.now()
        self.save(update_fields=["last_heartbeat"])


class Screenshot(models.Model):
    """
    Visual evidence attached to a SubProject (and optionally to a specific vulnerability).
    """

    subproject = models.ForeignKey(SubProject, on_delete=models.CASCADE, related_name="screenshots")
    # vulnerability FK added in vulnerabilities app via generic relation to avoid circular import
    vulnerability_ref = models.PositiveIntegerField(null=True, blank=True, help_text="FK to Vulnerability.id")

    image = models.ImageField(upload_to="projects/screenshots/")
    caption = models.CharField(max_length=512, blank=True)
    order = models.PositiveSmallIntegerField(default=0)

    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="uploaded_screenshots",
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Screenshot"
        verbose_name_plural = "Screenshots"
        ordering = ["order", "uploaded_at"]

    def __str__(self) -> str:
        return f"Screenshot({self.subproject_id}, order={self.order})"
