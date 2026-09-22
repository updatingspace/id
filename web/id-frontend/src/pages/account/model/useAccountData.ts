import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../../lib/api';
import type { AccountSection, Preferences } from './types';

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

const retryQuery = (failures: number, error: Error) => {
  const status = (error as Error & { status?: number }).status;
  return status !== 401 && status !== 403 && failures < 1;
};

export const useAccountData = (enabled: boolean, section: AccountSection, identity: string) => {
  const client = useQueryClient();
  const preferences = useQuery({
    queryKey: [...accountKeys.preferences, identity],
    queryFn: api.getPreferences,
    enabled: enabled && section === 'privacy',
    retry: retryQuery,
    staleTime: 60_000,
  });

  const consents = useQuery({
    queryKey: [...accountKeys.consents, identity],
    queryFn: api.getConsents,
    enabled: enabled && section === 'privacy',
    retry: retryQuery,
    staleTime: 30_000,
  });

  const sessions = useQuery({
    queryKey: [...accountKeys.sessions, identity],
    queryFn: api.getSessions,
    enabled: enabled && section === 'sessions',
    retry: retryQuery,
    staleTime: 10_000,
  });

  const apps = useQuery({
    queryKey: [...accountKeys.apps, identity],
    queryFn: api.getOAuthApps,
    enabled: enabled && section === 'apps',
    retry: retryQuery,
    staleTime: 30_000,
  });

  const history = useQuery({
    queryKey: [...accountKeys.history, identity],
    queryFn: api.getLoginHistory,
    enabled: enabled && section === 'sessions',
    retry: retryQuery,
    staleTime: 30_000,
  });

  const mfa = useQuery({
    queryKey: [...accountKeys.mfa, identity],
    queryFn: api.mfaStatus,
    enabled: enabled && (section === 'security' || section === 'data'),
    retry: retryQuery,
    staleTime: 10_000,
  });

  const passkeys = useQuery({
    queryKey: [...accountKeys.passkeys, identity],
    queryFn: api.passkeysList,
    enabled: enabled && section === 'security',
    retry: retryQuery,
    staleTime: 10_000,
  });

  const providers = useQuery({
    queryKey: [...accountKeys.providers, identity],
    queryFn: api.getOAuthProviders,
    enabled: enabled && section === 'security',
    retry: retryQuery,
    staleTime: 60_000,
  });

  const timezones = useQuery({
    queryKey: [...accountKeys.timezones, identity],
    queryFn: api.getTimezones,
    enabled: enabled && section === 'privacy',
    retry: retryQuery,
    staleTime: 24 * 60_000,
  });

  const emailStatus = useQuery({
    queryKey: [...accountKeys.emailStatus, identity],
    queryFn: api.emailStatus,
    enabled: enabled && (section === 'profile' || section === 'security'),
    retry: retryQuery,
    staleTime: 10_000,
  });

  const queries = { preferences, consents, sessions, apps, history, mfa, passkeys, providers, timezones, emailStatus };
  const sectionQueries = {
    profile: [emailStatus],
    security: [mfa, passkeys, providers, emailStatus],
    privacy: [preferences, timezones, consents],
    sessions: [sessions, history],
    apps: [apps],
    data: [mfa],
  }[section];

  return {
    ...queries,
    setPreferences: (value: Preferences) => client.setQueryData([...accountKeys.preferences, identity], value),
    error: sectionQueries.find((query) => query.isError)?.error,
    retry: () => Promise.all(sectionQueries.map((query) => query.refetch())),
  };
};
