import { useQuery } from '@tanstack/react-query';
import { api } from '../../../lib/api';

export const accountKeys = {
  preferences: ['account', 'preferences'] as const,
  consents: ['account', 'consents'] as const,
  sessions: ['account', 'sessions'] as const,
  apps: ['account', 'apps'] as const,
  history: ['account', 'history'] as const,
  mfa: ['account', 'mfa'] as const,
  passkeys: ['account', 'passkeys'] as const,
  providers: ['account', 'providers'] as const,
  timezones: ['account', 'timezones'] as const,
  emailStatus: ['account', 'emailStatus'] as const,
};

export const useAccountData = (enabled: boolean) => {
  const preferences = useQuery({
    queryKey: accountKeys.preferences,
    queryFn: api.getPreferences,
    enabled,
    staleTime: 60_000,
  });

  const consents = useQuery({
    queryKey: accountKeys.consents,
    queryFn: api.getConsents,
    enabled,
    staleTime: 30_000,
  });

  const sessions = useQuery({
    queryKey: accountKeys.sessions,
    queryFn: api.getSessions,
    enabled,
    staleTime: 10_000,
  });

  const apps = useQuery({
    queryKey: accountKeys.apps,
    queryFn: api.getOAuthApps,
    enabled,
    staleTime: 30_000,
  });

  const history = useQuery({
    queryKey: accountKeys.history,
    queryFn: api.getLoginHistory,
    enabled,
    staleTime: 30_000,
  });

  const mfa = useQuery({
    queryKey: accountKeys.mfa,
    queryFn: api.mfaStatus,
    enabled,
    staleTime: 10_000,
  });

  const passkeys = useQuery({
    queryKey: accountKeys.passkeys,
    queryFn: api.passkeysList,
    enabled,
    staleTime: 10_000,
  });

  const providers = useQuery({
    queryKey: accountKeys.providers,
    queryFn: api.getOAuthProviders,
    enabled,
    staleTime: 60_000,
  });

  const timezones = useQuery({
    queryKey: accountKeys.timezones,
    queryFn: api.getTimezones,
    enabled,
    staleTime: 24 * 60_000,
  });

  const emailStatus = useQuery({
    queryKey: accountKeys.emailStatus,
    queryFn: api.emailStatus,
    enabled,
    staleTime: 10_000,
  });

  const anyInitialLoading =
    preferences.isLoading ||
    consents.isLoading ||
    sessions.isLoading ||
    apps.isLoading ||
    history.isLoading ||
    mfa.isLoading ||
    passkeys.isLoading ||
    providers.isLoading ||
    timezones.isLoading ||
    emailStatus.isLoading;

  return {
    anyInitialLoading,
    preferences,
    consents,
    sessions,
    apps,
    history,
    mfa,
    passkeys,
    providers,
    timezones,
    emailStatus,
  };
};
