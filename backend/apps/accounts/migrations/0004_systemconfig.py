from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0003_passwordresettoken_temp_password"),
    ]

    operations = [
        migrations.CreateModel(
            name="SystemConfig",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "backup_max_files",
                    models.PositiveIntegerField(
                        default=5,
                        help_text="Number of pg_dump backups to keep before rotating (1-100).",
                    ),
                ),
            ],
            options={
                "verbose_name": "System configuration",
            },
        ),
    ]
