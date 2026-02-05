from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("updspaceid", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="oauthstate",
            name="redirect_uri",
            field=models.TextField(blank=True),
        ),
    ]
