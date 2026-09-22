const toBytes = (input: string): ArrayBuffer => {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes.buffer;
};

const toBase64Url = (value: ArrayBuffer): string => {
  const bytes = new Uint8Array(value);
  let raw = '';
  bytes.forEach((b) => {
    raw += String.fromCharCode(b);
  });
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};

export const mapRequestOptions = (input: Record<string, unknown>): PublicKeyCredentialRequestOptions => {
  const mapped = unwrapPublicKey(input);

  if (typeof mapped.challenge === 'string') {
    mapped.challenge = toBytes(mapped.challenge);
  }

  const allowCredentials = mapped.allowCredentials;
  if (Array.isArray(allowCredentials)) {
    mapped.allowCredentials = allowCredentials.map((cred) => {
      if (!cred || typeof cred !== 'object') {
        return cred;
      }
      const out = { ...(cred as Record<string, unknown>) };
      if (typeof out.id === 'string') {
        out.id = toBytes(out.id);
      }
      return out;
    });
  }

  return mapped as unknown as PublicKeyCredentialRequestOptions;
};

export const mapCreationOptions = (input: Record<string, unknown>): PublicKeyCredentialCreationOptions => {
  const mapped = unwrapPublicKey(input);

  if (typeof mapped.challenge === 'string') {
    mapped.challenge = toBytes(mapped.challenge);
  }

  if (mapped.user && typeof mapped.user === 'object') {
    const user = { ...(mapped.user as Record<string, unknown>) };
    if (typeof user.id === 'string') {
      user.id = toBytes(user.id);
    }
    mapped.user = user;
  }

  const excludeCredentials = mapped.excludeCredentials;
  if (Array.isArray(excludeCredentials)) {
    mapped.excludeCredentials = excludeCredentials.map((cred) => {
      if (!cred || typeof cred !== 'object') {
        return cred;
      }
      const out = { ...(cred as Record<string, unknown>) };
      if (typeof out.id === 'string') {
        out.id = toBytes(out.id);
      }
      return out;
    });
  }

  return mapped as unknown as PublicKeyCredentialCreationOptions;
};

const unwrapPublicKey = (input: Record<string, unknown>): Record<string, unknown> => {
  const options = input.publicKey ?? input;
  if (!options || typeof options !== 'object' || !('challenge' in options)) {
    throw new Error('Сервер не вернул параметры Passkey. Повторите попытку.');
  }
  return { ...options };
};

export const serializeCredential = (credential: PublicKeyCredential): Record<string, unknown> => {
  const response = credential.response;
  const base = {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: credential.authenticatorAttachment,
  };

  if (response instanceof AuthenticatorAttestationResponse) {
    return {
      ...base,
      response: {
        clientDataJSON: toBase64Url(response.clientDataJSON),
        attestationObject: toBase64Url(response.attestationObject),
        transports: response.getTransports?.() ?? [],
      },
    };
  }

  if (response instanceof AuthenticatorAssertionResponse) {
    return {
      ...base,
      response: {
        clientDataJSON: toBase64Url(response.clientDataJSON),
        authenticatorData: toBase64Url(response.authenticatorData),
        signature: toBase64Url(response.signature),
        userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
      },
    };
  }

  return base;
};
