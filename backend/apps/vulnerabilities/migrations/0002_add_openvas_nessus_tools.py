"""
Migration: add OpenVAS and Nessus to ScanImport.Tool choices.
TextChoices don't require a schema change — this migration is a no-op
but documents the addition for historical accuracy.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0001_initial"),
    ]

    operations = [
        # TextChoices are validated at the application layer only;
        # the DB column is VARCHAR with no constraint.  No schema change needed.
    ]
