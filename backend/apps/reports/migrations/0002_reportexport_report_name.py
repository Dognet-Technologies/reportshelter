from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("reports", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="reportexport",
            name="report_name",
            field=models.CharField(
                blank=True,
                default="",
                help_text="Human-readable name set at generation time.",
                max_length=200,
            ),
        ),
    ]
