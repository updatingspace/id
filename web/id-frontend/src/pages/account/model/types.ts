export type TimezoneRow = { name: string; display_name: string; offset: string };
export type ProviderRow = { id: string; name: string };

export type EmailStatus = { email: string; verified: boolean };

export type AccountSection = 'profile' | 'security' | 'privacy' | 'sessions' | 'apps' | 'data';
