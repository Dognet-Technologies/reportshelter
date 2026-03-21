"""
Migration: register OpenVAS and Nessus tool choices in the migration state.

Migration 0002 documented these additions as a no-op (empty operations) because
TextChoices don't generate DB schema changes on PostgreSQL.  However, Django's
migration framework compares choices stored in migration state against the Python
model and raises a "changes not reflected in a migration" warning when they differ.

This migration records the AlterField so Django's internal state matches the model,
eliminating the spurious warning.  No SQL is executed against the database.
"""

import django.db.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0005_scanimport_celery_task_id_drop_not_null"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scanimport",
            name="tool",
            field=models.CharField(
                choices=[
                    ("nmap", "Nmap"),
                    ("nikto", "Nikto"),
                    ("burp", "Burp Suite"),
                    ("zap", "OWASP ZAP"),
                    ("metasploit", "Metasploit"),
                    ("csv", "Generic CSV"),
                    ("openvas", "OpenVAS / Greenbone"),
                    ("nessus", "Nessus"),
                    ("unknown", "Unknown"),
                ],
                default="unknown",
                max_length=32,
            ),
        ),
    ]
