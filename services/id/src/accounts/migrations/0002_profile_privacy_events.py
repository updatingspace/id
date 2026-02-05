from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="birth_date",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="country_code",
            field=models.CharField(blank=True, max_length=2),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="phone_number",
            field=models.CharField(blank=True, max_length=32),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="phone_verified",
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name="AccountDeletionRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Ожидание"),
                            ("executed", "Выполнено"),
                            ("canceled", "Отменено"),
                        ],
                        default="pending",
                        max_length=16,
                    ),
                ),
                (
                    "requested_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                ("executed_at", models.DateTimeField(blank=True, null=True)),
                ("reason", models.CharField(blank=True, max_length=256)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="deletion_requests",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Запрос на удаление аккаунта",
                "verbose_name_plural": "Запросы на удаление аккаунта",
            },
        ),
        migrations.CreateModel(
            name="AccountEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("action", models.CharField(max_length=64)),
                ("meta", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="account_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Событие аккаунта",
                "verbose_name_plural": "События аккаунта",
            },
        ),
        migrations.CreateModel(
            name="DataExportRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Ожидание"),
                            ("ready", "Готово"),
                            ("failed", "Ошибка"),
                        ],
                        default="pending",
                        max_length=16,
                    ),
                ),
                (
                    "requested_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("format", models.CharField(default="json", max_length=16)),
                ("error", models.CharField(blank=True, max_length=256)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="data_exports",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Запрос на экспорт данных",
                "verbose_name_plural": "Запросы на экспорт данных",
            },
        ),
        migrations.CreateModel(
            name="LoginEvent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("success", "Успешный вход"),
                            ("failure", "Ошибка входа"),
                        ],
                        max_length=16,
                    ),
                ),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("ip_hash", models.CharField(blank=True, max_length=64)),
                ("user_agent", models.CharField(blank=True, max_length=512)),
                ("device_id", models.CharField(blank=True, max_length=64)),
                ("location", models.CharField(blank=True, max_length=128)),
                ("is_new_device", models.BooleanField(default=False)),
                ("reason", models.CharField(blank=True, max_length=64)),
                ("meta", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="login_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Событие входа",
                "verbose_name_plural": "События входа",
            },
        ),
        migrations.CreateModel(
            name="UserConsent",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "kind",
                    models.CharField(
                        choices=[
                            ("data_processing", "Согласие на обработку данных"),
                            ("marketing", "Согласие на маркетинг"),
                            ("parental", "Согласие родителя/опекуна"),
                        ],
                        max_length=32,
                    ),
                ),
                ("version", models.CharField(blank=True, max_length=32)),
                ("granted_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("source", models.CharField(blank=True, max_length=64)),
                ("meta", models.JSONField(default=dict)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="consents",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Согласие пользователя",
                "verbose_name_plural": "Согласия пользователей",
            },
        ),
        migrations.CreateModel(
            name="UserDevice",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("device_id", models.CharField(max_length=64)),
                ("user_agent", models.CharField(blank=True, max_length=512)),
                ("first_seen", models.DateTimeField(default=django.utils.timezone.now)),
                ("last_seen", models.DateTimeField(blank=True, null=True)),
                ("last_ip", models.GenericIPAddressField(blank=True, null=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="devices",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Устройство пользователя",
                "verbose_name_plural": "Устройства пользователей",
            },
        ),
        migrations.CreateModel(
            name="UserPreferences",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("language", models.CharField(default="en", max_length=8)),
                ("timezone", models.CharField(blank=True, max_length=64)),
                ("marketing_opt_in", models.BooleanField(default=False)),
                ("marketing_opt_in_at", models.DateTimeField(blank=True, null=True)),
                ("marketing_opt_out_at", models.DateTimeField(blank=True, null=True)),
                ("privacy_scope_defaults", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="preferences",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Предпочтения пользователя",
                "verbose_name_plural": "Предпочтения пользователей",
            },
        ),
        migrations.AddIndex(
            model_name="accountdeletionrequest",
            index=models.Index(
                fields=["status", "requested_at"], name="acct_delete_status_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="accountevent",
            index=models.Index(
                fields=["action", "created_at"], name="acct_event_action_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="accountevent",
            index=models.Index(
                fields=["user", "created_at"], name="acct_event_user_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="dataexportrequest",
            index=models.Index(
                fields=["user", "requested_at"], name="acct_export_user_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="dataexportrequest",
            index=models.Index(
                fields=["status", "requested_at"], name="acct_export_status_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="loginevent",
            index=models.Index(
                fields=["user", "created_at"], name="acct_login_user_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="loginevent",
            index=models.Index(
                fields=["status", "created_at"], name="acct_login_status_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="userconsent",
            index=models.Index(
                fields=["user", "kind"], name="acct_consent_user_kind_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="userconsent",
            index=models.Index(
                fields=["kind", "granted_at"], name="acct_consent_kind_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="userdevice",
            index=models.Index(
                fields=["user", "last_seen"], name="acct_device_user_last_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="userdevice",
            constraint=models.UniqueConstraint(
                fields=("user", "device_id"), name="acct_device_user_device_uniq"
            ),
        ),
    ]
