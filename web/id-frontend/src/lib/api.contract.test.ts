import { beforeEach, describe, expect, it, vi } from 'vitest';

import { api } from './api';

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

describe('api contract', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it('uses GET with query params for oidc prepare', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        jsonResponse({
          request_id: 'req-1',
          client: { client_id: 'portal', name: 'Portal' },
          scopes: [],
          consent_required: false,
          redirect_uri: 'https://app.example/cb',
        }),
      );

    await api.oidcPrepare({
      client_id: 'portal',
      redirect_uri: 'https://app.example/cb',
      response_type: 'code',
      scope: 'openid profile',
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.startsWith('/oauth/authorize/prepare?')).toBe(true);
    const parsed = new URL(url, 'https://id.localhost');
    expect(parsed.searchParams.get('client_id')).toBe('portal');
    expect(parsed.searchParams.get('response_type')).toBe('code');
    expect(parsed.searchParams.get('scope')).toBe('openid profile');
    expect(init.method).toBeUndefined();
  });

  it('unwraps /auth/me payload and returns user profile', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      jsonResponse({
        user: { email: 'user@example.com', first_name: 'User' },
      }),
    );

    const profile = await api.profile();
    expect(profile.email).toBe('user@example.com');
    expect(profile.first_name).toBe('User');
  });

  it('sends X-Session-Token when session token exists', async () => {
    window.sessionStorage.setItem('id_session_token', 'session-1');
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(jsonResponse({ language: 'en' }));

    await api.getPreferences();

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get('X-Session-Token')).toBe('session-1');
  });

  it('matches backend payload for email change and sessions bulk revoke', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));

    await api.changeEmail('next@example.com');
    await api.revokeOtherSessions();

    const [emailUrl, emailInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(emailUrl).toBe('/api/v1/auth/email/change');
    expect(emailInit.method).toBe('POST');
    expect(JSON.parse(String(emailInit.body))).toEqual({ new_email: 'next@example.com' });

    const [bulkUrl, bulkInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(bulkUrl).toBe('/api/v1/auth/sessions/bulk');
    expect(bulkInit.method).toBe('POST');
    expect(JSON.parse(String(bulkInit.body))).toEqual({ all_except_current: true });
  });
});
