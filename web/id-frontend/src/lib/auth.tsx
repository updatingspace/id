import React, { createContext, useContext, useEffect, useState } from 'react';

import { api } from './api';
import { clearSessionToken, getSessionToken, setSessionToken } from './session';

export type AuthUser = {
  id?: string;
  email?: string;
  username?: string;
  first_name?: string;
  last_name?: string;
  phone_number?: string;
  birth_date?: string;
  email_verified?: boolean;
  has_2fa?: boolean;
  oauth_providers?: string[];
  avatar_url?: string;
  is_staff?: boolean;
  is_superuser?: boolean;
};

export type AuthResult = {
  ok: boolean;
  code?: string;
  message?: string;
  recoveryCodes?: string[];
};

export type SignupPayload = {
  email: string;
  password: string;
  username?: string;
  language?: 'ru' | 'en';
  timezone?: string;
  consentDataProcessing?: boolean;
  consentMarketing?: boolean;
  isMinor?: boolean;
  guardianEmail?: string;
  guardianConsent?: boolean;
  birthDate?: string;
};

type AuthContextValue = {
  user: AuthUser | null;
  loading: boolean;
  refresh: () => Promise<void>;
  login: (email: string, password: string, totpCode?: string, recoveryCode?: string) => Promise<AuthResult>;
  signup: (payload: SignupPayload) => Promise<AuthResult>;
  logout: () => Promise<void>;
};

export const AuthContext = createContext<AuthContextValue | undefined>(undefined);
type AuthApiError = Error & { code?: string; status?: number };

const AUTH_ERROR_CODES = new Set(['UNAUTHORIZED', 'INVALID_SESSION', 'INVALID_TOKEN', 'TOKEN_EXPIRED']);

const toAuthResult = (err: unknown, fallback: string): AuthResult => {
  const message = err instanceof Error ? err.message : fallback;
  const code =
    err && typeof err === 'object' && 'code' in err && typeof err.code === 'string'
      ? err.code
      : undefined;
  return { ok: false, code, message };
};

const isAuthFailure = (err: unknown): boolean => {
  if (!err || typeof err !== 'object') {
    return false;
  }
  const apiErr = err as AuthApiError;
  if (apiErr.status === 401 || apiErr.status === 403) {
    return true;
  }
  if (apiErr.code && AUTH_ERROR_CODES.has(apiErr.code)) {
    return true;
  }
  return false;
};

export const AuthProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = async (): Promise<void> => {
    const token = getSessionToken();

    try {
      const profile = await api.profile();
      setUser(profile as AuthUser);
    } catch (err) {
      if (isAuthFailure(err)) {
        if (token) {
          clearSessionToken();
        }
        setUser(null);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const login = async (
    email: string,
    password: string,
    totpCode?: string,
    recoveryCode?: string,
  ): Promise<AuthResult> => {
    try {
      const { form_token } = await api.getFormToken('login');
      const response = await api.headlessLogin({
        email,
        password,
        mfa_code: totpCode,
        recovery_code: recoveryCode,
        form_token,
      });

      const token = response.meta?.session_token || response.session_token;
      if (token) {
        setSessionToken(token);
      }

      await refresh();

      return {
        ok: true,
        recoveryCodes: response.recovery_codes,
      };
    } catch (err) {
      return toAuthResult(err, 'Login failed');
    }
  };

  const signup = async (payload: SignupPayload): Promise<AuthResult> => {
    try {
      const { form_token } = await api.getFormToken('register');
      const response = await api.signup({
        username: payload.username,
        email: payload.email,
        password: payload.password,
        form_token,
        language: payload.language,
        timezone: payload.timezone,
        consent_data_processing: payload.consentDataProcessing,
        consent_marketing: payload.consentMarketing,
        is_minor: payload.isMinor,
        guardian_email: payload.guardianEmail,
        guardian_consent: payload.guardianConsent,
        birth_date: payload.birthDate,
      });

      const token = response.meta?.session_token || response.session_token;
      if (token) {
        setSessionToken(token);
      }

      await refresh();
      return { ok: true };
    } catch (err) {
      return toAuthResult(err, 'Signup failed');
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await api.logout();
    } catch {
      // logout should always clear local auth state
    } finally {
      clearSessionToken();
      setUser(null);
    }
  };

  const value: AuthContextValue = {
    user,
    loading,
    refresh,
    login,
    signup,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextValue => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return ctx;
};
