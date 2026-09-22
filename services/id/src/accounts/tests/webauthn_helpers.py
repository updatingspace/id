"""Ephemeral software credentials for local WebAuthn integration checks."""

import hashlib
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.utils import websafe_encode
from fido2.webauthn import (
    Aaguid,
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
    CollectedClientData,
)


@dataclass
class VirtualPasskey:
    private_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    user_handle: str = ""
    rp_id: str = ""

    def register(self, options, *, origin="https://testserver"):
        self.user_handle = options["user"]["id"]
        self.rp_id = options["rp"]["id"]
        credential = AttestedCredentialData.create(
            Aaguid.NONE,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key()),
        )
        auth_data = AuthenticatorData.create(
            hashlib.sha256(self.rp_id.encode()).digest(),
            AuthenticatorData.FLAG.UP
            | AuthenticatorData.FLAG.UV
            | AuthenticatorData.FLAG.AT,
            0,
            credential,
        )
        client_data = CollectedClientData.create(
            type="webauthn.create", challenge=options["challenge"], origin=origin
        )
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client_data),
                "attestationObject": websafe_encode(
                    AttestationObject.create("none", auth_data, {})
                ),
                "transports": ["internal"],
            },
            "clientExtensionResults": {"credProps": {"rk": True}},
        }

    def authenticate(self, options, *, origin="https://testserver"):
        client_data = CollectedClientData.create(
            type="webauthn.get", challenge=options["challenge"], origin=origin
        )
        auth_data = AuthenticatorData.create(
            hashlib.sha256(self.rp_id.encode()).digest(),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV,
            1,
        )
        signature = self.private_key.sign(
            auth_data + client_data.hash, ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": websafe_encode(self.credential_id),
            "rawId": websafe_encode(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": websafe_encode(client_data),
                "authenticatorData": websafe_encode(auth_data),
                "signature": websafe_encode(signature),
                "userHandle": self.user_handle,
            },
            "clientExtensionResults": {},
        }
