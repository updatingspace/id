import { describe, expect, it, beforeEach, vi } from 'vitest';
import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
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
    vi.resetAllMocks();
    vi.mocked(getSessionToken).mockReturnValue(null);
    vi.mocked(setSessionToken).mockImplementation((token) => {
      vi.mocked(getSessionToken).mockReturnValue(token);
    });
    vi.mocked(clearSessionToken).mockImplementation(() => {
      vi.mocked(getSessionToken).mockReturnValue(null);
    });
  });

  it('renders a guest immediately without calling the token-only profile endpoint', async () => {
    vi.mocked(getSessionToken).mockReturnValue(null);
    vi.mocked(api.profile).mockResolvedValue({ email: 'cookie-user@example.com' });

    render(
      <AuthProvider>
        <Probe />
      </AuthProvider>,
    );

    await waitFor(() => {
      expect(screen.getByText('guest')).toBeInTheDocument();
    });
    expect(api.profile).not.toHaveBeenCalled();
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

  it.each(['login', 'signup'] as const)('uses the profile returned by %s without another /me request', async (method) => {
    vi.mocked(api.getFormToken).mockResolvedValue({ form_token: 'ft', expires_in: 900 });
    const response = { meta: { session_token: 'new-session' }, user: { email: 'new@example.com' } };
    vi.mocked(api.headlessLogin).mockResolvedValue(response);
    vi.mocked(api.signup).mockResolvedValue(response);
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await act(async () => {
      if (method === 'login') await result.current.login('new@example.com', 'password');
      else await result.current.signup({ email: 'new@example.com', password: 'password' });
    });
    expect(result.current.user?.email).toBe('new@example.com');
    expect(api.profile).not.toHaveBeenCalled();
  });

  it('falls back to /me when login returns no profile', async () => {
    vi.mocked(api.getFormToken).mockResolvedValue({ form_token: 'ft', expires_in: 900 });
    vi.mocked(api.headlessLogin).mockResolvedValue({ meta: { session_token: 'new-session' }, user: null });
    vi.mocked(api.profile).mockResolvedValue({ email: 'fallback@example.com' });
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await act(async () => { await result.current.login('fallback@example.com', 'password'); });
    expect(result.current.user?.email).toBe('fallback@example.com');
    expect(api.profile).toHaveBeenCalledTimes(1);
  });

  it('offers a retry after a session timeout without dropping the token', async () => {
    vi.mocked(getSessionToken).mockReturnValue('session-1');
    vi.mocked(api.profile)
      .mockRejectedValueOnce(Object.assign(new Error('timeout'), { code: 'REQUEST_TIMEOUT' }))
      .mockResolvedValueOnce({ email: 'retry@example.com' });
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await waitFor(() => expect(result.current.error).toBe('auth.sessionUnavailable'));
    expect(result.current.user).toBeNull();
    expect(result.current.loading).toBe(false);
    expect(clearSessionToken).not.toHaveBeenCalled();
    await act(async () => { await result.current.refresh(); });
    expect(result.current.user?.email).toBe('retry@example.com');
    expect(result.current.error).toBeNull();
  });

  it('does not restore a user from a stale request after logout', async () => {
    vi.mocked(getSessionToken).mockReturnValue('session-1');
    let finish!: (profile: Record<string, unknown>) => void;
    vi.mocked(api.profile).mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await waitFor(() => expect(api.profile).toHaveBeenCalled());
    await act(async () => { await result.current.logout(); });
    await act(async () => { finish({ email: 'stale@example.com' }); });
    expect(result.current.user).toBeNull();
    expect(result.current.loading).toBe(false);
  });

  it('does not clear a new login when an old session request returns 401', async () => {
    vi.mocked(getSessionToken).mockReturnValue('old-session');
    let fail!: (error: Error) => void;
    vi.mocked(api.profile).mockReturnValue(new Promise((_, reject) => { fail = reject; }));
    vi.mocked(api.getFormToken).mockResolvedValue({ form_token: 'ft', expires_in: 900 });
    vi.mocked(api.headlessLogin).mockResolvedValue({
      meta: { session_token: 'new-session' }, user: { email: 'new@example.com' },
    });
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await waitFor(() => expect(api.profile).toHaveBeenCalled());
    await act(async () => { await result.current.login('new@example.com', 'password'); });
    await act(async () => { fail(asAuthError(401, 'INVALID_SESSION')); });
    expect(result.current.user?.email).toBe('new@example.com');
    expect(getSessionToken()).toBe('new-session');
    expect(clearSessionToken).not.toHaveBeenCalled();
  });

  it('does not accept a session when MFA is still required', async () => {
    vi.mocked(api.getFormToken).mockResolvedValue({ form_token: 'ft', expires_in: 900 });
    vi.mocked(api.headlessLogin).mockRejectedValue(asAuthError(401, 'MFA_REQUIRED'));
    const { result } = renderHook(() => useAuth(), { wrapper: AuthProvider });
    await act(async () => {
      expect(await result.current.login('user@example.com', 'password')).toMatchObject({ ok: false, code: 'MFA_REQUIRED' });
    });
    expect(setSessionToken).not.toHaveBeenCalled();
    expect(result.current.user).toBeNull();
  });
});
