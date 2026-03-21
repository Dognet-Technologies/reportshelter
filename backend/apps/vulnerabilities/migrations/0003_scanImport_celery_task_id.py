"""
Migration: add celery_task_id to ScanImport so tasks can be revoked.

The column is nullable so that existing code paths that do not set the field
(e.g. old container code, or InsertS that omit the column) never raise a
NOT NULL constraint violation.  The application always sets it to the Celery
task UUID or leaves it NULL; both are valid.
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
            field=models.CharField(blank=True, null=True, default=None, max_length=255),
        ),
    ]
