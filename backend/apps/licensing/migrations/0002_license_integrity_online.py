"""
Add integrity_hash and last_online_checked_at fields to License.

integrity_hash        — HMAC-SHA256 tamper-detection field.
last_online_checked_at — timestamp of the last successful DLM server check.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("licensing", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="license",
            name="integrity_hash",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="license",
            name="last_online_checked_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
