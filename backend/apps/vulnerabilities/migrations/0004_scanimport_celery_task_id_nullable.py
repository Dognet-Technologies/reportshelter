"""
Migration: make celery_task_id nullable.

0003 created the column as NOT NULL without a DB-level default, which causes
IntegrityError on any INSERT that omits the field (e.g. old container code).
This migration drops the NOT NULL constraint by altering the column to NULL.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0003_scanImport_celery_task_id"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scanimport",
            name="celery_task_id",
            field=models.CharField(blank=True, null=True, default=None, max_length=255),
        ),
    ]
