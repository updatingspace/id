import type {
  ConsentRow,
  EmailStatus,
  ExportPayloadResponse,
  LoginHistoryRow,
  MfaStatus,
  OAuthAppRow,
  OAuthLinkResponse,
  PasskeyRow,
  Preferences,
  ProviderRow,
  SessionRow,
  TimezoneRow,
  TotpBeginResponse,
  TotpConfirmResponse,
} from '../pages/account/model/types';
import { getSessionToken } from './session';

type ApiError = Error & { code?: string; status?: number };
type OidcScope = { name: string; description: string; required: boolean; granted: boolean };
type OidcPrepareResponse = {
  request_id: string;
  client: { client_id: string; name: string; logo_url?: string };
  scopes: OidcScope[];
  consent_required: boolean;
  redirect_uri: string;
};

const API_BASE = import.meta.env.VITE_ID_API_BASE_URL ?? '/api/v1';
const OIDC_BASE = import.meta.env.VITE_ID_OIDC_BASE_URL ?? '/oauth';

const withQuery = (path: string, query: Record<string, string | undefined>) => {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== '') {
      params.set(key, value);
    }
  });
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
};

const buildHeaders = (headers?: HeadersInit, body?: BodyInit | null): Headers => {
  const built = new Headers(headers ?? {});
  if (body !== undefined && body !== null && !built.has('Content-Type')) {
    built.set('Content-Type', 'application/json');
  }
  const sessionToken = getSessionToken();
  if (sessionToken && !built.has('X-Session-Token')) {
    built.set('X-Session-Token', sessionToken);
  }
  return built;
};

const toError = async (res: Response): Promise<ApiError> => {
  let code: string | undefined;
  let message = `HTTP ${res.status}`;
  try {
    const body = await res.json();
    if (body?.error?.code) {
      code = String(body.error.code);
      message = body.error.message ?? message;
    } else if (body?.code) {
      code = String(body.code);
      message = body.message ?? message;
    } else if (body?.message) {
      message = body.message;
    }
  } catch {
    // ignore non-json body
  }
  const error = new Error(message) as ApiError;
  error.code = code;
  error.status = res.status;
  return error;
};

const request = async <T>(path: string, init?: RequestInit): Promise<T> => {
  const res = await fetch(path, {
    credentials: 'include',
    ...init,
    headers: buildHeaders(init?.headers, init?.body),
  });

  if (!res.ok) {
    throw await toError(res);
  }

  if (res.status === 204) {
    return {} as T;
  }

  return (await res.json()) as T;
};

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) });

const patch = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'PATCH', body: body === undefined ? undefined : JSON.stringify(body) });

const del = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'DELETE', body: body === undefined ? undefined : JSON.stringify(body) });

export const api = {
  getOAuthProviders: () => request<{ providers: ProviderRow[] }>(`${API_BASE}/auth/oauth/providers`).catch(() => ({ providers: [] })),
  getOAuthLoginUrl: (providerId: string, next?: string) =>
    request<OAuthLinkResponse>(withQuery(`${API_BASE}/auth/oauth/login/${providerId}`, { next })),

  passkeyLoginBegin: () => post<{ request_options: Record<string, unknown> }>(`${API_BASE}/auth/passkeys/login/begin`),
  passkeyLoginComplete: (credential: unknown) =>
    post<{ access_token?: string; session_token?: string; meta?: { session_token?: string } }>(
      `${API_BASE}/auth/passkeys/login/complete`,
      { credential },
    ),

  headlessLogin: (payload: {
    email: string;
    password: string;
    totp_code?: string;
    recovery_code?: string;
  }) => post<{ ok?: boolean; code?: string; message?: string; session_token?: string; recovery_codes?: string[] }>(`${API_BASE}/auth/login`, payload),

  signup: (payload: Record<string, unknown>) => post<{ ok?: boolean; code?: string; message?: string }>(`${API_BASE}/auth/signup`, payload),
  profile: async () => {
    const payload = await request<{ user: Record<string, unknown> | null }>(`${API_BASE}/auth/me`);
    if (!payload.user) {
      const err = new Error('Not authenticated') as ApiError;
      err.code = 'UNAUTHORIZED';
      err.status = 401;
      throw err;
    }
    return payload.user;
  },
  logout: () => post(`${API_BASE}/auth/logout`),

  oidcPrepare: (query: Record<string, string>) =>
    request<OidcPrepareResponse>(withQuery(`${OIDC_BASE}/authorize/prepare`, query)),
  oidcApprove: (payload: { request_id: string; scopes: string[]; remember: boolean }) =>
    post<{ redirect_uri: string }>(`${OIDC_BASE}/authorize/approve`, payload),
  oidcDeny: (requestId: string) => post<{ redirect_uri: string }>(`${OIDC_BASE}/authorize/deny`, { request_id: requestId }),

  updateProfile: (payload: Record<string, unknown>) => patch(`${API_BASE}/auth/profile`, payload),
  changePassword: (currentPassword: string, nextPassword: string) =>
    post(`${API_BASE}/auth/change_password`, {
      current_password: currentPassword,
      new_password: nextPassword,
    }),

  getPreferences: () => request<Preferences>(`${API_BASE}/auth/preferences`).catch(() => ({})),
  updatePreferences: (payload: Preferences) => patch<Preferences>(`${API_BASE}/auth/preferences`, payload),

  getConsents: () => request<{ consents: ConsentRow[] }>(`${API_BASE}/auth/consents`).catch(() => ({ consents: [] })),
  revokeConsent: (kind: string) => post(withQuery(`${API_BASE}/auth/consents/revoke`, { kind })),

  getSessions: () => request<{ sessions: SessionRow[] }>(`${API_BASE}/auth/sessions`).catch(() => ({ sessions: [] })),
  revokeSession: (id: string) => del(`${API_BASE}/auth/sessions/${id}`),
  revokeOtherSessions: () => post(`${API_BASE}/auth/sessions/bulk`, { all_except_current: true }),

  getOAuthApps: () => request<{ items: OAuthAppRow[] }>(`${API_BASE}/auth/oauth/apps`).catch(() => ({ items: [] })),
  revokeOAuthApp: (clientId: string) => post(`${API_BASE}/auth/oauth/apps/revoke`, { client_id: clientId }),

  getLoginHistory: () => request<{ events: LoginHistoryRow[] }>(`${API_BASE}/auth/login-history`).catch(() => ({ events: [] })),
  mfaStatus: () => request<MfaStatus>(`${API_BASE}/auth/mfa/status`),

  passkeysList: () => request<{ authenticators: PasskeyRow[] }>(`${API_BASE}/auth/passkeys`).catch(() => ({ authenticators: [] })),
  passkeysBegin: (passwordless: boolean) =>
    post<{ creation_options: Record<string, unknown> }>(`${API_BASE}/auth/passkeys/begin`, {
      passwordless,
    }),
  passkeysComplete: (name: string, credential: unknown) => post(`${API_BASE}/auth/passkeys/complete`, { name, credential }),
  passkeysDelete: (ids: string[]) => post(`${API_BASE}/auth/passkeys/delete`, { ids }),

  getTimezones: () => request<{ timezones: TimezoneRow[] }>(`${API_BASE}/auth/timezones`).catch(() => ({ timezones: [] })),
  emailStatus: () => request<EmailStatus>(`${API_BASE}/auth/email`),
  resendEmailVerification: () => post(`${API_BASE}/auth/email/resend`),
  changeEmail: (newEmail: string) => post(`${API_BASE}/auth/email/change`, { new_email: newEmail }),

  totpBegin: () => post<TotpBeginResponse>(`${API_BASE}/auth/mfa/totp/begin`),
  totpConfirm: (code: string) => post<TotpConfirmResponse>(`${API_BASE}/auth/mfa/totp/confirm`, { code }),
  totpDisable: () => post<void>(`${API_BASE}/auth/mfa/totp/disable`),
  recoveryRegenerate: () => post<{ recovery_codes: string[] }>(`${API_BASE}/auth/mfa/recovery/regenerate`),

  getOAuthLinkUrl: (providerId: string, redirectPath: string) =>
    request<OAuthLinkResponse>(withQuery(`${API_BASE}/auth/oauth/link/${providerId}`, { next: redirectPath })),
  unlinkOAuthProvider: (providerId: string) => post(`${API_BASE}/auth/oauth/unlink`, { provider: providerId }),

  dataExport: (payload: { password: string; mfa_code?: string }) =>
    post<ExportPayloadResponse>(`${API_BASE}/auth/data/export`, payload),
  deleteAccount: (payload: { password: string; mfa_code?: string; reason: string }) =>
    post<void>(`${API_BASE}/auth/account/delete`, payload),
};
