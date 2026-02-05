from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("updspaceid", "0003_add_outbox_event"),
    ]

    operations = [
        migrations.AddField(
            model_name="magiclinktoken",
            name="skip_context_validation",
            field=models.BooleanField(default=False),
        ),
    ]
