import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PropsWithChildren } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../../lib/api';
import { useAccountData } from './useAccountData';
import type { AccountSection } from './types';

describe('account data loading', () => {
  beforeEach(() => {
    vi.spyOn(api, 'emailStatus').mockResolvedValue({ email: 'user@example.com', verified: true });
    vi.spyOn(api, 'getSessions').mockResolvedValue({ sessions: [] });
    vi.spyOn(api, 'getLoginHistory').mockResolvedValue({ events: [] });
    vi.spyOn(api, 'getPreferences');
    vi.spyOn(api, 'mfaStatus');
    vi.spyOn(api, 'passkeysList');
    vi.spyOn(api, 'getOAuthProviders');
    vi.spyOn(api, 'getOAuthApps');
    vi.spyOn(api, 'getConsents');
    vi.spyOn(api, 'getTimezones');
  });
  afterEach(() => vi.restoreAllMocks());

  const setup = (enabled = true) => {
    const client = new QueryClient();
    const wrapper = ({ children }: PropsWithChildren) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    return renderHook(
      ({ section, identity }) => useAccountData(enabled, section, identity),
      { wrapper, initialProps: { section: 'profile' as AccountSection, identity: 'user@example.com' } },
    );
  };

  it('loads only the active section and fetches sessions when selected', async () => {
    const { result, rerender } = setup();
    await waitFor(() => expect(result.current.emailStatus.isSuccess).toBe(true));
    for (const fn of [api.getSessions, api.getLoginHistory, api.getPreferences, api.mfaStatus,
      api.passkeysList, api.getOAuthProviders, api.getOAuthApps, api.getConsents, api.getTimezones]) {
      expect(fn).not.toHaveBeenCalled();
    }
    rerender({ section: 'sessions', identity: 'user@example.com' });
    await waitFor(() => expect(result.current.history.isSuccess).toBe(true));
    expect(api.getSessions).toHaveBeenCalledTimes(1);
    expect(api.getLoginHistory).toHaveBeenCalledTimes(1);
    expect(api.getPreferences).not.toHaveBeenCalled();
  });

  it('does not fetch private data before authentication', () => {
    setup(false);
    expect(api.emailStatus).not.toHaveBeenCalled();
    expect(api.getSessions).not.toHaveBeenCalled();
  });

  it('does not reuse another account cache', async () => {
    const { result, rerender } = setup();
    await waitFor(() => expect(result.current.emailStatus.isSuccess).toBe(true));
    vi.mocked(api.emailStatus).mockResolvedValue({ email: 'other@example.com', verified: false });
    rerender({ section: 'profile', identity: 'other@example.com' });
    await waitFor(() => expect(result.current.emailStatus.data?.email).toBe('other@example.com'));
    expect(api.emailStatus).toHaveBeenCalledTimes(2);
  });

  it('surfaces a rejected session without automatic retries and supports explicit retry', async () => {
    vi.mocked(api.emailStatus).mockRejectedValueOnce(Object.assign(new Error('expired'), { status: 401 }));
    const { result } = setup();
    await waitFor(() => expect(result.current.error).toBeTruthy());
    expect(api.emailStatus).toHaveBeenCalledTimes(1);
    await act(async () => { await result.current.retry(); });
    await waitFor(() => expect(result.current.error).toBeUndefined());
    expect(result.current.emailStatus.data?.email).toBe('user@example.com');
  });
});
