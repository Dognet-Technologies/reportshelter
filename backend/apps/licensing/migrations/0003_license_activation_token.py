from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("licensing", "0002_license_integrity_online"),
    ]

    operations = [
        migrations.AddField(
            model_name="license",
            name="activation_token",
            field=models.CharField(
                blank=True,
                default="",
                max_length=255,
                help_text="Opaque token returned by the DLM /activate endpoint. Used for /validate and /deactivate.",
            ),
        ),
    ]
