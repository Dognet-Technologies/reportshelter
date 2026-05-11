"""
Models for the vulnerabilities app.
Defines the Vulnerability model with CVSS/EPSS scoring, deduplication,
diff/timeline logic, and ScanImport tracking.
"""

from __future__ import annotations

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import Case, IntegerField, Value, When
from django.utils import timezone

# Maps risk_level to a numeric weight for semantic ordering (critical first).
RISK_LEVEL_ORDER = Case(
    When(risk_level="critical", then=Value(0)),
    When(risk_level="high", then=Value(1)),
    When(risk_level="medium", then=Value(2)),
    When(risk_level="low", then=Value(3)),
    When(risk_level="info", then=Value(4)),
    default=Value(5),
    output_field=IntegerField(),
)


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
        # Extended tool support
        ACUNETIX = "acunetix", "Acunetix / Acunetix 360"
        ARACHNI = "arachni", "Arachni"
        AWS_INSPECTOR2 = "aws_inspector2", "AWS Inspector v2"
        AWSSECURITYHUB = "awssecurityhub", "AWS Security Hub"
        CARGO_AUDIT = "cargo_audit", "Cargo Audit"
        CLOUDSPLOIT = "cloudsploit", "CloudSploit"
        COBALT = "cobalt", "Cobalt.io"
        CODECHECKER = "codechecker", "CodeChecker"
        CYCOGNITO = "cycognito", "CyCognito"
        DOCKERBENCH = "dockerbench", "Docker Bench Security"
        GITHUB_VULNERABILITY = "github_vulnerability", "GitHub Security Alerts"
        GITLAB_CONTAINER_SCAN = "gitlab_container_scan", "GitLab Container Scan"
        GITLEAKS = "gitleaks", "Gitleaks"
        HYDRA = "hydra", "Hydra"
        IMMUNIWEB = "immuniweb", "ImmuniWeb"
        NETSPARKER = "netsparker", "Netsparker / Invicti"
        NEXPOSE = "nexpose", "Nexpose / InsightVM"
        NUCLEI = "nuclei", "Nuclei"
        QUALYS = "qualys", "Qualys Infrastructure"
        QUALYS_WEBAPP = "qualys_webapp", "Qualys Web App Scanner"
        REDHATSATELLITE = "redhatsatellite", "Red Hat Satellite"
        SONARQUBE = "sonarqube", "SonarQube"
        SSH_AUDIT = "ssh_audit", "ssh-audit"
        SSLSCAN = "sslscan", "SSLScan"
        SYSDIG = "sysdig", "Sysdig"
        TRIVY = "trivy", "Trivy"
        WAPITI = "wapiti", "Wapiti"
        WFUZZ = "wfuzz", "Wfuzz"
        WPSCAN = "wpscan", "WPScan"
        PENTEST_PIPELINE = "pentest_pipeline", "Pentest Pipeline Report (MD)"
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
    celery_task_id = models.CharField(max_length=255, blank=True, null=True, default=None)

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

    class EnrichmentStatus(models.TextChoices):
        PENDING = "pending", "Pending"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"
        SKIPPED = "skipped", "Skipped"
        PARTIAL = "partial", "Partial"

    class EffortLevel(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"

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
    affected_ip = models.CharField(max_length=45, blank=True, help_text="Raw IP address (IPv4/IPv6)")
    affected_host = models.CharField(max_length=255, blank=True)
    affected_port = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(65535)],
    )
    affected_service = models.CharField(max_length=128, blank=True)

    # Category — CWE / OWASP Top 10 / MASVS / custom (for vulns_by_category chart)
    category = models.CharField(
        max_length=128,
        blank=True,
        help_text="Vulnerability category: CWE-ID, OWASP Top 10 label, MASVS control, etc.",
    )

    # Manual risk matrix axes (1-5 each; used to plot the 5×5 risk_matrix chart)
    # If not set by a parser, the generator derives them from CVSS/EPSS.
    likelihood = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Likelihood of exploitation (1=Very Low … 5=Very High).",
    )
    impact = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
        help_text="Business impact if exploited (1=Negligible … 5=Critical).",
    )

    # Estimated remediation effort — set manually or inferred from severity
    effort_level = models.CharField(
        max_length=8,
        choices=EffortLevel.choices,
        blank=True,
        help_text="Estimated effort to remediate: low / medium / high.",
    )

    # CVE list / CVSS
    cve_id = models.JSONField(default=list, help_text="List of CVE identifiers, e.g. ['CVE-2022-1234']")
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

    # NVD enrichment tracking
    nvd_enrichment_status = models.CharField(
        max_length=16,
        choices=EnrichmentStatus.choices,
        default=EnrichmentStatus.PENDING,
    )
    is_kev = models.BooleanField(
        default=False,
        help_text="True if listed in the CISA Known Exploited Vulnerabilities catalog.",
    )
    cve_published = models.DateField(
        null=True,
        blank=True,
        help_text="CVE publication date from NVD (populated by enrichment task).",
    )

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

    # MITRE ATT&CK mapping (manual or parser-populated)
    mitre_tactic = models.CharField(
        max_length=128, blank=True,
        help_text="ATT&CK Tactic name, e.g. 'Initial Access'",
    )
    mitre_technique_id = models.CharField(
        max_length=32, blank=True,
        help_text="ATT&CK Technique ID, e.g. 'T1190'",
    )
    mitre_technique_name = models.CharField(
        max_length=255, blank=True,
        help_text="ATT&CK Technique name, e.g. 'Exploit Public-Facing Application'",
    )

    # Screenshots are linked via Screenshot.vulnerability_ref
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Vulnerability"
        verbose_name_plural = "Vulnerabilities"
        ordering = [
            models.F("risk_score").desc(nulls_last=True),
            models.F("cvss_score").desc(nulls_last=True),
            "title",
        ]
        indexes = [
            models.Index(fields=["subproject", "title", "affected_ip", "affected_host", "affected_port"]),
            models.Index(fields=["vuln_status"]),
            models.Index(fields=["risk_level"]),
        ]

    def __str__(self) -> str:
        return f"[{self.risk_level.upper()}] {self.title} @ {self.affected_host}"

    @property
    def primary_cve_id(self) -> str:
        """Return the first CVE ID in the list, or empty string."""
        return self.cve_id[0] if self.cve_id else ""

    @property
    def dedup_key(self) -> tuple[str, str, str]:
        """Uniqueness key for deduplication within a subproject."""
        host = (self.affected_ip or self.affected_host).lower().strip()
        port = str(self.affected_port) if self.affected_port else ""
        return (self.title.lower().strip(), host, port)

    def effective_likelihood(self) -> int:
        """
        Return the stored likelihood (1-5), or derive it from EPSS when absent.
        EPSS → likelihood mapping: [0,0.1) → 1, [0.1,0.3) → 2, [0.3,0.6) → 3,
        [0.6,0.85) → 4, [0.85,1] → 5.
        Falls back to risk_level-derived value when EPSS is also unavailable.
        """
        if self.likelihood is not None:
            return self.likelihood
        epss = self.epss_score
        if epss is not None:
            if epss < 0.10:
                return 1
            if epss < 0.30:
                return 2
            if epss < 0.60:
                return 3
            if epss < 0.85:
                return 4
            return 5
        # Fallback: derive from risk_level
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1}.get(self.risk_level, 2)

    def effective_impact(self) -> int:
        """
        Return the stored impact (1-5), or derive it from CVSS score when absent.
        CVSS → impact mapping: [0,2) → 1, [2,4) → 2, [4,6) → 3, [6,9) → 4, [9,10] → 5.
        Falls back to risk_level-derived value when CVSS is also unavailable.
        """
        if self.impact is not None:
            return self.impact
        cvss = self.cvss_score
        if cvss is not None:
            if cvss < 2.0:
                return 1
            if cvss < 4.0:
                return 2
            if cvss < 6.0:
                return 3
            if cvss < 9.0:
                return 4
            return 5
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(self.risk_level, 3)

    def effective_effort_level(self) -> str:
        """
        Return the stored effort_level, or derive from risk_level when blank.
        Critical/High → high, Medium → medium, Low/Info → low.
        """
        if self.effort_level:
            return self.effort_level
        return {"critical": "high", "high": "high", "medium": "medium",
                "low": "low", "info": "low"}.get(self.risk_level, "medium")

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
        # Auto-set enrichment status on creation based on CVE list presence
        if not self.pk and not self.cve_id:
            self.nvd_enrichment_status = self.EnrichmentStatus.SKIPPED
        # Auto-compute risk score before saving
        if self.cvss_score is not None or self.epss_score is not None:
            self.risk_score = self.compute_risk_score()
        super().save(*args, **kwargs)


class EngagementEvent(models.Model):
    """
    A chronological event recorded during the engagement (for Attack Timeline).
    Events can be linked to an ATT&CK phase and optionally to a Vulnerability.
    """

    class Phase(models.TextChoices):
        RECON            = "recon",                 "Reconnaissance"
        INITIAL_ACCESS   = "initial_access",        "Initial Access"
        EXECUTION        = "execution",             "Execution"
        PERSISTENCE      = "persistence",           "Persistence"
        PRIV_ESC         = "privilege_escalation",  "Privilege Escalation"
        DEFENSE_EVASION  = "defense_evasion",       "Defense Evasion"
        CREDENTIAL_ACCESS= "credential_access",     "Credential Access"
        DISCOVERY        = "discovery",             "Discovery"
        LATERAL_MOVEMENT = "lateral_movement",      "Lateral Movement"
        COLLECTION       = "collection",            "Collection"
        EXFILTRATION     = "exfiltration",          "Exfiltration"
        IMPACT           = "impact",                "Impact"
        OTHER            = "other",                 "Other"

    subproject = models.ForeignKey(
        "projects.SubProject",
        on_delete=models.CASCADE,
        related_name="engagement_events",
    )
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="engagement_events",
    )

    timestamp    = models.DateTimeField(null=True, blank=True)
    phase        = models.CharField(max_length=32, choices=Phase.choices, default=Phase.OTHER)
    title        = models.CharField(max_length=255)
    description  = models.TextField(blank=True)
    tool_used    = models.CharField(max_length=128, blank=True)
    affected_host= models.CharField(max_length=255, blank=True)
    order        = models.PositiveSmallIntegerField(default=0, help_text="Manual sort order")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Engagement Event"
        verbose_name_plural = "Engagement Events"
        ordering = ["order", "timestamp", "created_at"]

    def __str__(self) -> str:
        ts = self.timestamp.strftime("%Y-%m-%d %H:%M") if self.timestamp else "—"
        return f"[{self.phase}] {self.title} ({ts})"


class IndicatorOfCompromise(models.Model):
    """
    IoC entries for the Indicators of Compromise report section.
    Covers network indicators, file artifacts, credential indicators, and TTPs.
    """

    class IndicatorType(models.TextChoices):
        IP           = "ip",           "IP Address"
        DOMAIN       = "domain",       "Domain"
        URL          = "url",          "URL"
        FILE_HASH    = "file_hash",    "File Hash"
        EMAIL        = "email",        "Email Address"
        USER_AGENT   = "user_agent",   "User Agent"
        REGISTRY_KEY = "registry_key", "Registry Key"
        MUTEX        = "mutex",        "Mutex"
        TTP          = "ttp",          "MITRE TTP"
        OTHER        = "other",        "Other"

    class Confidence(models.TextChoices):
        HIGH   = "high",   "High"
        MEDIUM = "medium", "Medium"
        LOW    = "low",    "Low"

    subproject = models.ForeignKey(
        "projects.SubProject",
        on_delete=models.CASCADE,
        related_name="iocs",
    )

    ioc_type        = models.CharField(max_length=16, choices=IndicatorType.choices, default=IndicatorType.OTHER)
    value           = models.CharField(max_length=1024, help_text="The raw IoC value (IP, hash, domain, etc.)")
    description     = models.TextField(blank=True)
    confidence      = models.CharField(max_length=8, choices=Confidence.choices, blank=True)
    source          = models.CharField(max_length=128, blank=True, help_text="Tool or assessor that identified this IoC")
    mitre_technique = models.CharField(max_length=64, blank=True, help_text="Related ATT&CK technique ID")
    first_seen      = models.DateTimeField(null=True, blank=True)
    last_seen       = models.DateTimeField(null=True, blank=True)
    tags            = models.JSONField(default=list)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Indicator of Compromise"
        verbose_name_plural = "Indicators of Compromise"
        ordering = ["ioc_type", "value"]

    def __str__(self) -> str:
        return f"[{self.ioc_type}] {self.value[:80]}"


class RiskEntry(models.Model):
    """
    Risk register entry — tracks accepted, mitigated, or open risks for a SubProject.
    """

    class RiskLevel(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH     = "high",     "High"
        MEDIUM   = "medium",   "Medium"
        LOW      = "low",      "Low"

    class RiskStatus(models.TextChoices):
        OPEN        = "open",        "Open"
        ACCEPTED    = "accepted",    "Accepted"
        MITIGATED   = "mitigated",   "Mitigated"
        TRANSFERRED = "transferred", "Transferred"

    subproject = models.ForeignKey(
        "projects.SubProject",
        on_delete=models.CASCADE,
        related_name="risk_entries",
    )
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="risk_entries",
        help_text="Linked finding (optional — risk may be independent of a specific vuln)",
    )

    title       = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    risk_level  = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.MEDIUM)
    likelihood  = models.IntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
    )
    impact      = models.IntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)],
    )
    status      = models.CharField(max_length=16, choices=RiskStatus.choices, default=RiskStatus.OPEN)
    owner       = models.CharField(max_length=255, blank=True)
    mitigation  = models.TextField(blank=True)
    target_date = models.DateField(null=True, blank=True)

    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Risk Entry"
        verbose_name_plural = "Risk Entries"
        ordering = [
            Case(
                When(risk_level="critical", then=Value(0)),
                When(risk_level="high",     then=Value(1)),
                When(risk_level="medium",   then=Value(2)),
                When(risk_level="low",      then=Value(3)),
                default=Value(4),
                output_field=IntegerField(),
            ),
        ]

    def __str__(self) -> str:
        return f"[{self.risk_level.upper()}] {self.title}"


class ComplianceControl(models.Model):
    """
    A single compliance framework control assessed during the engagement.
    Multiple findings (Vulnerabilities) can be linked to one control.
    """

    class ControlStatus(models.TextChoices):
        COMPLIANT     = "compliant",     "Compliant"
        NON_COMPLIANT = "non_compliant", "Non-Compliant"
        PARTIAL       = "partial",       "Partial"
        NOT_ASSESSED  = "not_assessed",  "Not Assessed"

    subproject = models.ForeignKey(
        "projects.SubProject",
        on_delete=models.CASCADE,
        related_name="compliance_controls",
    )
    findings = models.ManyToManyField(
        Vulnerability,
        blank=True,
        related_name="compliance_controls",
    )

    framework    = models.CharField(max_length=64, help_text="e.g. PCI-DSS, ISO 27001, NIST CSF")
    control_id   = models.CharField(max_length=64, help_text="e.g. 6.3.1, A.12.6.1, PR.AC-1")
    control_name = models.CharField(max_length=255)
    description  = models.TextField(blank=True)
    status       = models.CharField(max_length=16, choices=ControlStatus.choices, default=ControlStatus.NOT_ASSESSED)
    evidence     = models.TextField(blank=True)
    notes        = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Compliance Control"
        verbose_name_plural = "Compliance Controls"
        ordering = ["framework", "control_id"]

    def __str__(self) -> str:
        return f"[{self.framework}] {self.control_id} — {self.control_name}"
