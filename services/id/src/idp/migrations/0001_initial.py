from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import idp.models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="OidcClient",
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
                    "client_id",
                    models.CharField(
                        default=idp.models.generate_client_id,
                        editable=False,
                        max_length=64,
                        unique=True,
                    ),
                ),
                ("client_secret_hash", models.CharField(blank=True, max_length=256)),
                ("name", models.CharField(max_length=128)),
                ("description", models.CharField(blank=True, max_length=256)),
                ("logo_url", models.URLField(blank=True)),
                ("redirect_uris", models.JSONField(default=list)),
                ("allowed_scopes", models.JSONField(default=list)),
                ("grant_types", models.JSONField(default=list)),
                ("response_types", models.JSONField(default=list)),
                ("is_public", models.BooleanField(default=True)),
                ("is_first_party", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "OIDC клиент",
                "verbose_name_plural": "OIDC клиенты",
            },
        ),
        migrations.CreateModel(
            name="OidcAuthorizationRequest",
            fields=[
                (
                    "request_id",
                    models.CharField(
                        editable=False, max_length=64, primary_key=True, serialize=False
                    ),
                ),
                ("redirect_uri", models.TextField()),
                ("scope", models.TextField()),
                ("state", models.CharField(blank=True, max_length=256)),
                ("nonce", models.CharField(blank=True, max_length=256)),
                ("code_challenge", models.CharField(blank=True, max_length=256)),
                ("code_challenge_method", models.CharField(blank=True, max_length=16)),
                ("prompt", models.CharField(blank=True, max_length=32)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("expires_at", models.DateTimeField()),
                (
                    "client",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="idp.oidcclient"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "OIDC запрос авторизации",
                "verbose_name_plural": "OIDC запросы авторизации",
            },
        ),
        migrations.CreateModel(
            name="OidcAuthorizationCode",
            fields=[
                (
                    "code",
                    models.CharField(max_length=128, primary_key=True, serialize=False),
                ),
                ("redirect_uri", models.TextField()),
                ("scope", models.TextField()),
                ("nonce", models.CharField(blank=True, max_length=256)),
                ("code_challenge", models.CharField(blank=True, max_length=256)),
                ("code_challenge_method", models.CharField(blank=True, max_length=16)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("expires_at", models.DateTimeField()),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "client",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="idp.oidcclient"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "OIDC код авторизации",
                "verbose_name_plural": "OIDC коды авторизации",
            },
        ),
        migrations.CreateModel(
            name="OidcConsent",
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
                ("scopes", models.JSONField(default=list)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "client",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="idp.oidcclient"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "OIDC согласие",
                "verbose_name_plural": "OIDC согласия",
            },
        ),
        migrations.CreateModel(
            name="OidcToken",
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
                ("access_jti", models.CharField(db_index=True, max_length=128)),
                ("id_jti", models.CharField(blank=True, max_length=128)),
                ("refresh_token_hash", models.CharField(blank=True, max_length=256)),
                ("scope", models.TextField()),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("access_expires_at", models.DateTimeField()),
                ("refresh_expires_at", models.DateTimeField(blank=True, null=True)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                (
                    "client",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="idp.oidcclient"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "OIDC токен",
                "verbose_name_plural": "OIDC токены",
            },
        ),
        migrations.AddIndex(
            model_name="oidcclient",
            index=models.Index(fields=["client_id"], name="oidc_client_id_idx"),
        ),
        migrations.AddIndex(
            model_name="oidcauthorizationrequest",
            index=models.Index(
                fields=["client", "expires_at"], name="oidc_req_client_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="oidcauthorizationrequest",
            index=models.Index(fields=["user", "expires_at"], name="oidc_req_user_idx"),
        ),
        migrations.AddIndex(
            model_name="oidcauthorizationcode",
            index=models.Index(
                fields=["client", "expires_at"], name="oidc_code_client_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="oidcauthorizationcode",
            index=models.Index(
                fields=["user", "expires_at"], name="oidc_code_user_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="oidcconsent",
            index=models.Index(
                fields=["user", "updated_at"], name="oidc_consent_user_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="oidcconsent",
            constraint=models.UniqueConstraint(
                fields=("user", "client"), name="oidc_consent_user_client_uniq"
            ),
        ),
        migrations.AddIndex(
            model_name="oidctoken",
            index=models.Index(fields=["access_jti"], name="oidc_token_access_idx"),
        ),
        migrations.AddIndex(
            model_name="oidctoken",
            index=models.Index(
                fields=["refresh_expires_at"], name="oidc_token_refresh_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="oidctoken",
            index=models.Index(
                fields=["user", "client"], name="oidc_token_user_client_idx"
            ),
        ),
    ]
