import { describe, expect, it } from 'vitest';
import { mapCreationOptions, mapRequestOptions } from './webauthn';

const bytes = (value: ArrayBuffer) => Array.from(new Uint8Array(value));

describe('WebAuthn options from the ID API', () => {
  it('unwraps registration options and decodes all binary fields without mutating the response', () => {
    const publicKey = {
      challenge: '-_8',
      rp: { id: 'id.example.com', name: 'UpdSpace ID' },
      user: { id: 'AQI', name: 'user@example.com', displayName: 'User' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      excludeCredentials: [{ type: 'public-key', id: 'AwQ', transports: ['internal'] }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      extensions: { credProps: true },
    };
    const options = mapCreationOptions({ publicKey });
    expect(bytes(options.challenge as ArrayBuffer)).toEqual([251, 255]);
    expect(bytes(options.user.id as ArrayBuffer)).toEqual([1, 2]);
    expect(bytes(options.excludeCredentials![0].id as ArrayBuffer)).toEqual([3, 4]);
    expect(options.authenticatorSelection?.residentKey).toBe('required');
    expect(options.extensions).toEqual({ credProps: true });
    expect(options).not.toHaveProperty('publicKey');
    expect(publicKey.challenge).toBe('-_8');
    expect(publicKey.user.id).toBe('AQI');
  });

  it('unwraps login options and preserves transports', () => {
    const options = mapRequestOptions({ publicKey: {
      challenge: 'AQI', rpId: 'id.example.com',
      allowCredentials: [{ type: 'public-key', id: 'AwQ', transports: ['usb'] }],
    } });
    expect(bytes(options.challenge as ArrayBuffer)).toEqual([1, 2]);
    expect(bytes(options.allowCredentials![0].id as ArrayBuffer)).toEqual([3, 4]);
    expect(options.allowCredentials![0].transports).toEqual(['usb']);
  });

  it('also accepts publicKey options directly', () => {
    expect(bytes(mapRequestOptions({ challenge: 'AQI' }).challenge as ArrayBuffer)).toEqual([1, 2]);
  });

  it('rejects missing challenge before calling browser credentials APIs', () => {
    expect(() => mapCreationOptions({ publicKey: {} })).toThrow('параметры Passkey');
    expect(() => mapRequestOptions({})).toThrow('параметры Passkey');
  });
});
