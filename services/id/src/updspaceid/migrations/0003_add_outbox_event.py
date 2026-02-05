from __future__ import annotations

from django.db import migrations, models
import django.utils.timezone
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("updspaceid", "0002_add_oauthstate_redirect_uri"),
    ]

    operations = [
        migrations.CreateModel(
            name="OutboxEvent",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("event_type", models.CharField(max_length=64)),
                ("payload_json", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("processed_at", models.DateTimeField(blank=True, null=True)),
                ("attempts", models.IntegerField(default=0)),
                ("last_error", models.TextField(blank=True)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="outbox_events",
                        to="updspaceid.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "usid_outbox",
                "indexes": [
                    models.Index(
                        fields=["event_type", "created_at"],
                        name="usid_outbox_type_created_idx",
                    ),
                    models.Index(
                        fields=["tenant", "created_at"],
                        name="usid_outbox_tenant_created_idx",
                    ),
                    models.Index(
                        fields=["processed_at"],
                        name="usid_outbox_processed_idx",
                    ),
                ],
            },
        ),
    ]
