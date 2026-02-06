import { describe, expect, it, beforeEach, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import React from 'react';

vi.mock('./api', () => ({
  api: {
    profile: vi.fn(),
    getFormToken: vi.fn(),
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
import { clearSessionToken, getSessionToken, setSessionToken } from './session';
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

const ProbeActions = () => {
  const { loading, login, signup } = useAuth();
  if (loading) {
    return <span>loading</span>;
  }
  return (
    <>
      <button type="button" onClick={() => void login('u@example.com', 'Password123!', '123456')}>
        do-login
      </button>
      <button
        type="button"
        onClick={() =>
          void signup({
            email: 'new@example.com',
            password: 'Password123!',
            username: 'new-user',
            language: 'ru',
            timezone: 'UTC',
            consentDataProcessing: true,
          })
        }
      >
        do-signup
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

  it('requests form token for login and stores meta session token', async () => {
    vi.mocked(getSessionToken).mockReturnValue(null);
    vi.mocked(api.profile).mockResolvedValue({ email: 'guest@example.com' });
    vi.mocked(api.getFormToken).mockResolvedValue({ form_token: 'ft-login', expires_in: 900 });
    vi.mocked(api.headlessLogin).mockResolvedValue({
      meta: { session_token: 'session-login' },
      recovery_codes: [],
    });

    render(
      <AuthProvider>
        <ProbeActions />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'do-login' })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'do-login' }));

    await waitFor(() => {
      expect(api.getFormToken).toHaveBeenCalledWith('login');
      expect(api.headlessLogin).toHaveBeenCalledWith({
        email: 'u@example.com',
        password: 'Password123!',
        mfa_code: '123456',
        recovery_code: undefined,
        form_token: 'ft-login',
      });
      expect(setSessionToken).toHaveBeenCalledWith('session-login');
    });
  });

  it('requests form token for signup and uses backend snake_case payload', async () => {
    vi.mocked(getSessionToken).mockReturnValue(null);
    vi.mocked(api.profile).mockResolvedValue({ email: 'guest@example.com' });
    vi.mocked(api.getFormToken).mockResolvedValue({ form_token: 'ft-signup', expires_in: 900 });
    vi.mocked(api.signup).mockResolvedValue({
      meta: { session_token: 'session-signup' },
    });

    render(
      <AuthProvider>
        <ProbeActions />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'do-signup' })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: 'do-signup' }));

    await waitFor(() => {
      expect(api.getFormToken).toHaveBeenCalledWith('register');
      expect(api.signup).toHaveBeenCalledWith({
        username: 'new-user',
        email: 'new@example.com',
        password: 'Password123!',
        form_token: 'ft-signup',
        language: 'ru',
        timezone: 'UTC',
        consent_data_processing: true,
        consent_marketing: undefined,
        is_minor: undefined,
        guardian_email: undefined,
        guardian_consent: undefined,
        birth_date: undefined,
      });
      expect(setSessionToken).toHaveBeenCalledWith('session-signup');
    });
  });
});
