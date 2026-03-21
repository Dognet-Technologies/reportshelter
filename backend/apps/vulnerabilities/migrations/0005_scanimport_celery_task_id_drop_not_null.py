"""
Migration: forcefully drop NOT NULL on celery_task_id via raw SQL.

Migration 0003 added the column as NOT NULL, and 0004's AlterField may not
have generated the correct ALTER COLUMN ... DROP NOT NULL in PostgreSQL.
This migration uses RunSQL to explicitly fix the constraint at the DB level.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0004_scanimport_celery_task_id_nullable"),
    ]

    operations = [
        # Replace any existing NULL values with empty string first (safety)
        migrations.RunSQL(
            sql=(
                "UPDATE vulnerabilities_scanimport "
                "SET celery_task_id = '' "
                "WHERE celery_task_id IS NULL;"
            ),
            reverse_sql=migrations.RunSQL.noop,
        ),
        # Drop the NOT NULL constraint so the column truly accepts NULL
        migrations.RunSQL(
            sql=(
                "ALTER TABLE vulnerabilities_scanimport "
                "ALTER COLUMN celery_task_id DROP NOT NULL;"
            ),
            reverse_sql=(
                "ALTER TABLE vulnerabilities_scanimport "
                "ALTER COLUMN celery_task_id SET NOT NULL;"
            ),
        ),
    ]
