from django.contrib import admin

from idp.models import (
    OidcAuthorizationCode,
    OidcAuthorizationRequest,
    OidcClient,
    OidcConsent,
    OidcToken,
)


@admin.register(OidcClient)
class OidcClientAdmin(admin.ModelAdmin):
    list_display = ("client_id", "name", "is_public", "is_first_party", "created_at")
    search_fields = ("client_id", "name")
    list_filter = ("is_public", "is_first_party")


@admin.register(OidcConsent)
class OidcConsentAdmin(admin.ModelAdmin):
    list_display = ("user", "client", "updated_at", "last_used_at")
    search_fields = ("user__email", "client__name")
    list_filter = ("updated_at",)


@admin.register(OidcToken)
class OidcTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "client", "access_expires_at", "revoked_at")
    search_fields = ("access_jti", "user__email")
    list_filter = ("revoked_at",)


@admin.register(OidcAuthorizationRequest)
class OidcAuthorizationRequestAdmin(admin.ModelAdmin):
    list_display = ("request_id", "client", "user", "expires_at")
    search_fields = ("request_id",)


@admin.register(OidcAuthorizationCode)
class OidcAuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ("code", "client", "user", "expires_at", "used_at")
    search_fields = ("code",)
    list_filter = ("used_at",)
