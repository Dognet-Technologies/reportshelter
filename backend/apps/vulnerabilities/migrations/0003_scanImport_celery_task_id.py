"""
Migration: add celery_task_id to ScanImport so tasks can be revoked.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0002_add_openvas_nessus_tools"),
    ]

    operations = [
        migrations.AddField(
            model_name="scanimport",
            name="celery_task_id",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
