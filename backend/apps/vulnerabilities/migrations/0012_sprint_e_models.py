"""
Sprint E: add MITRE fields to Vulnerability + four new models:
  EngagementEvent, IndicatorOfCompromise, RiskEntry, ComplianceControl
"""

import django.core.validators
import django.db.models.deletion
import django.db.models.expressions
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0001_initial"),
        ("vulnerabilities", "0011_alter_scanimport_tool"),
    ]

    operations = [
        # ── MITRE fields on Vulnerability ───────────────────────────────
        migrations.AddField(
            model_name="vulnerability",
            name="mitre_tactic",
            field=models.CharField(
                blank=True,
                help_text="ATT&CK Tactic name, e.g. 'Initial Access'",
                max_length=128,
            ),
        ),
        migrations.AddField(
            model_name="vulnerability",
            name="mitre_technique_id",
            field=models.CharField(
                blank=True,
                help_text="ATT&CK Technique ID, e.g. 'T1190'",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="vulnerability",
            name="mitre_technique_name",
            field=models.CharField(
                blank=True,
                help_text="ATT&CK Technique name, e.g. 'Exploit Public-Facing Application'",
                max_length=255,
            ),
        ),

        # ── EngagementEvent ─────────────────────────────────────────────
        migrations.CreateModel(
            name="EngagementEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("timestamp", models.DateTimeField(blank=True, null=True)),
                ("phase", models.CharField(
                    choices=[
                        ("recon", "Reconnaissance"),
                        ("initial_access", "Initial Access"),
                        ("execution", "Execution"),
                        ("persistence", "Persistence"),
                        ("privilege_escalation", "Privilege Escalation"),
                        ("defense_evasion", "Defense Evasion"),
                        ("credential_access", "Credential Access"),
                        ("discovery", "Discovery"),
                        ("lateral_movement", "Lateral Movement"),
                        ("collection", "Collection"),
                        ("exfiltration", "Exfiltration"),
                        ("impact", "Impact"),
                        ("other", "Other"),
                    ],
                    default="other",
                    max_length=32,
                )),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("tool_used", models.CharField(blank=True, max_length=128)),
                ("affected_host", models.CharField(blank=True, max_length=255)),
                ("order", models.PositiveSmallIntegerField(default=0, help_text="Manual sort order")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("subproject", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="engagement_events",
                    to="projects.subproject",
                )),
                ("vulnerability", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="engagement_events",
                    to="vulnerabilities.vulnerability",
                )),
            ],
            options={
                "verbose_name": "Engagement Event",
                "verbose_name_plural": "Engagement Events",
                "ordering": ["order", "timestamp", "created_at"],
            },
        ),

        # ── IndicatorOfCompromise ────────────────────────────────────────
        migrations.CreateModel(
            name="IndicatorOfCompromise",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("ioc_type", models.CharField(
                    choices=[
                        ("ip", "IP Address"),
                        ("domain", "Domain"),
                        ("url", "URL"),
                        ("file_hash", "File Hash"),
                        ("email", "Email Address"),
                        ("user_agent", "User Agent"),
                        ("registry_key", "Registry Key"),
                        ("mutex", "Mutex"),
                        ("ttp", "MITRE TTP"),
                        ("other", "Other"),
                    ],
                    default="other",
                    max_length=16,
                )),
                ("value", models.CharField(
                    help_text="The raw IoC value (IP, hash, domain, etc.)",
                    max_length=1024,
                )),
                ("description", models.TextField(blank=True)),
                ("confidence", models.CharField(
                    blank=True,
                    choices=[("high", "High"), ("medium", "Medium"), ("low", "Low")],
                    max_length=8,
                )),
                ("source", models.CharField(
                    blank=True,
                    help_text="Tool or assessor that identified this IoC",
                    max_length=128,
                )),
                ("mitre_technique", models.CharField(
                    blank=True,
                    help_text="Related ATT&CK technique ID",
                    max_length=64,
                )),
                ("first_seen", models.DateTimeField(blank=True, null=True)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("tags", models.JSONField(default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("subproject", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="iocs",
                    to="projects.subproject",
                )),
            ],
            options={
                "verbose_name": "Indicator of Compromise",
                "verbose_name_plural": "Indicators of Compromise",
                "ordering": ["ioc_type", "value"],
            },
        ),

        # ── RiskEntry ────────────────────────────────────────────────────
        migrations.CreateModel(
            name="RiskEntry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("risk_level", models.CharField(
                    choices=[
                        ("critical", "Critical"),
                        ("high", "High"),
                        ("medium", "Medium"),
                        ("low", "Low"),
                    ],
                    default="medium",
                    max_length=16,
                )),
                ("likelihood", models.IntegerField(
                    blank=True,
                    null=True,
                    validators=[
                        django.core.validators.MinValueValidator(1),
                        django.core.validators.MaxValueValidator(5),
                    ],
                )),
                ("impact", models.IntegerField(
                    blank=True,
                    null=True,
                    validators=[
                        django.core.validators.MinValueValidator(1),
                        django.core.validators.MaxValueValidator(5),
                    ],
                )),
                ("status", models.CharField(
                    choices=[
                        ("open", "Open"),
                        ("accepted", "Accepted"),
                        ("mitigated", "Mitigated"),
                        ("transferred", "Transferred"),
                    ],
                    default="open",
                    max_length=16,
                )),
                ("owner", models.CharField(blank=True, max_length=255)),
                ("mitigation", models.TextField(blank=True)),
                ("target_date", models.DateField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("subproject", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="risk_entries",
                    to="projects.subproject",
                )),
                ("vulnerability", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="risk_entries",
                    to="vulnerabilities.vulnerability",
                )),
            ],
            options={
                "verbose_name": "Risk Entry",
                "verbose_name_plural": "Risk Entries",
            },
        ),

        # ── ComplianceControl ────────────────────────────────────────────
        migrations.CreateModel(
            name="ComplianceControl",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("framework", models.CharField(
                    help_text="e.g. PCI-DSS, ISO 27001, NIST CSF",
                    max_length=64,
                )),
                ("control_id", models.CharField(
                    help_text="e.g. 6.3.1, A.12.6.1, PR.AC-1",
                    max_length=64,
                )),
                ("control_name", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("status", models.CharField(
                    choices=[
                        ("compliant", "Compliant"),
                        ("non_compliant", "Non-Compliant"),
                        ("partial", "Partial"),
                        ("not_assessed", "Not Assessed"),
                    ],
                    default="not_assessed",
                    max_length=16,
                )),
                ("evidence", models.TextField(blank=True)),
                ("notes", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("subproject", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="compliance_controls",
                    to="projects.subproject",
                )),
                ("findings", models.ManyToManyField(
                    blank=True,
                    related_name="compliance_controls",
                    to="vulnerabilities.vulnerability",
                )),
            ],
            options={
                "verbose_name": "Compliance Control",
                "verbose_name_plural": "Compliance Controls",
                "ordering": ["framework", "control_id"],
            },
        ),
    ]
