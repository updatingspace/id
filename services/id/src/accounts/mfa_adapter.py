from __future__ import annotations

from allauth.mfa.adapter import DefaultMFAAdapter
from django.conf import settings


class CustomMFAAdapter(DefaultMFAAdapter):
    """
    Force a stable RP ID/name for WebAuthn so passkeys work on localhost:5173
    and similar dev origins.
    """

    def get_public_key_credential_rp_entity(self):
        rp_id = getattr(settings, "MFA_WEBAUTHN_RP_ID", "localhost")
        rp_name = getattr(settings, "MFA_WEBAUTHN_RP_NAME", "AEF Vote")
        return {"id": rp_id, "name": rp_name}

    def get_public_key_credential_rp_id(self):
        return getattr(settings, "MFA_WEBAUTHN_RP_ID", "localhost")


__all__ = ["CustomMFAAdapter"]
