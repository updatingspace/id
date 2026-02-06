import { describe, expect, it, beforeEach, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';

vi.mock('./api', () => ({
  api: {
    profile: vi.fn(),
    headlessLogin: vi.fn(),
    signup: vi.fn(),
    logout: vi.fn(),
  },
}));

vi.mock('./session', () => ({
  getSessionToken: vi.fn(),
  setSessionToken: vi.fn(),
  clearSessionToken: vi.fn(),
}));

import { api } from './api';
import { clearSessionToken, getSessionToken } from './session';
import { AuthProvider, useAuth } from './auth';

const Probe = () => {
  const { user, loading } = useAuth();
  if (loading) {
    return <span>loading</span>;
  }
  return <span>{user?.email ?? 'guest'}</span>;
};

const ProbeWithRefresh = () => {
  const { user, loading, refresh } = useAuth();
  if (loading) {
    return <span>loading</span>;
  }
  return (
    <>
      <span>{user?.email ?? 'guest'}</span>
      <button type="button" onClick={() => void refresh()}>
        refresh
      </button>
    </>
  );
};

const asAuthError = (status: number, code: string, message = 'auth error') =>
  Object.assign(new Error(message), { status, code });

describe('AuthProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('loads profile even without local token (cookie-only session)', async () => {
    vi.mocked(getSessionToken).mockReturnValue(null);
    vi.mocked(api.profile).mockResolvedValue({ email: 'cookie-user@example.com' });

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByText('cookie-user@example.com')).toBeInTheDocument();
    });
    expect(clearSessionToken).not.toHaveBeenCalled();
  });

  it('clears local token when refresh fails with auth error', async () => {
    vi.mocked(getSessionToken).mockReturnValue('token-1');
    vi.mocked(api.profile).mockRejectedValue(asAuthError(401, 'UNAUTHORIZED', 'unauthorized'));

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByText('guest')).toBeInTheDocument();
    });
    expect(clearSessionToken).toHaveBeenCalledTimes(1);
  });

  it('does not clear local token on transient backend error', async () => {
    vi.mocked(getSessionToken).mockReturnValue('token-1');
    vi.mocked(api.profile).mockRejectedValue(asAuthError(503, 'SERVER_ERROR', 'temporary issue'));

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByText('guest')).toBeInTheDocument();
    });
    expect(clearSessionToken).not.toHaveBeenCalled();
  });

  it('keeps current user on transient refresh failure', async () => {
    vi.mocked(getSessionToken).mockReturnValue('token-1');
    vi.mocked(api.profile)
      .mockResolvedValueOnce({ email: 'stable-user@example.com' })
      .mockRejectedValueOnce(asAuthError(503, 'SERVER_ERROR', 'temporary issue'));

    render(
      <AuthProvider>
        <ProbeWithRefresh />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByText('stable-user@example.com')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: 'refresh' }));

    await waitFor(() => {
      expect(vi.mocked(api.profile)).toHaveBeenCalledTimes(2);
    });

    expect(screen.getByText('stable-user@example.com')).toBeInTheDocument();
    expect(clearSessionToken).not.toHaveBeenCalled();
  });
});
