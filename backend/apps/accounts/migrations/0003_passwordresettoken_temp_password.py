from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_user_must_change_password_is_email_verified_default"),
    ]

    operations = [
        migrations.AddField(
            model_name="passwordresettoken",
            name="temp_password",
            field=models.CharField(default="", max_length=64),
        ),
    ]
