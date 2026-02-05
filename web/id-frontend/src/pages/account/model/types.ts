export type TimezoneRow = { name: string; display_name: string; offset: string };
export type ProviderRow = { id: string; name: string };

export type EmailStatus = { email: string; verified: boolean };

export type AccountSection = 'profile' | 'security' | 'privacy' | 'sessions' | 'apps' | 'data';

export type AccountUser = {
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

export type Preferences = {
  language?: 'ru' | 'en';
  timezone?: string;
  marketing_opt_in?: boolean;
  privacy_scope_defaults?: Record<string, 'allow' | 'ask' | 'deny'>;
};

export type ConsentRow = {
  kind: string;
  granted_at: string;
  revoked_at?: string | null;
};

export type SessionRow = {
  id: string;
  user_agent?: string;
  ip?: string;
  current?: boolean;
};

export type OAuthAppRow = {
  client_id: string;
  name: string;
  scopes: string[];
};

export type LoginHistoryRow = {
  created_at: string;
  status: string;
  ip_address?: string;
};

export type MfaStatus = {
  has_totp: boolean;
  has_webauthn: boolean;
  has_recovery_codes: boolean;
  recovery_codes_left: number;
};

export type PasskeyRow = {
  id: string;
  name?: string;
  is_passwordless?: boolean;
};

export type TotpBeginResponse = {
  secret: string;
  otpauth_url: string;
  svg: string;
  svg_data_uri: string;
};

export type TotpConfirmResponse = {
  recovery_codes?: string[];
};

export type OAuthLinkResponse = {
  authorize_url: string;
  method?: string;
};

export type ExportPayloadResponse = {
  payload?: unknown;
};
