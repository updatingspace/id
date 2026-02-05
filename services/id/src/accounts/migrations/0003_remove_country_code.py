from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0002_profile_privacy_events"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="userprofile",
            name="country_code",
        ),
    ]
