import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';

const reads = [
  ['preferences', api.getPreferences, { language: 'ru' }],
  ['consents', api.getConsents, { consents: [] }],
  ['sessions', api.getSessions, { sessions: [] }],
  ['oauth/apps', api.getOAuthApps, { items: [] }],
  ['login-history', api.getLoginHistory, { events: [] }],
  ['passkeys', api.passkeysList, { authenticators: [] }],
  ['timezones', api.getTimezones, { timezones: [] }],
  ['oauth/providers', api.getOAuthProviders, { providers: [] }],
] as const;

afterEach(() => vi.unstubAllGlobals());

describe.each(reads)('account read %s', (path, read, payload) => {
  it('preserves a successful empty response', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload)));
    vi.stubGlobal('fetch', fetch);
    await expect(read()).resolves.toEqual(payload);
    expect(fetch).toHaveBeenCalledWith(`/api/v1/auth/${path}`, expect.any(Object));
  });

  it.each([401, 403, 503])('reports HTTP %i instead of inventing empty data', async (status) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: { code: 'READ_FAILED', message: 'Unavailable' } }),
      { status },
    )));
    await expect(read()).rejects.toMatchObject({ status, code: 'READ_FAILED', message: 'Unavailable' });
  });

  it('preserves a network failure for the query retry flow', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
    await expect(read()).rejects.toThrow('Failed to fetch');
  });
});
