import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import AccountPage from './AccountPage';
import { AuthContext } from '../../lib/auth';
import { I18nProvider } from '../../lib/i18n';
import { api } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    updateProfile: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock('./model/useAccountData', () => ({
  useAccountData: vi.fn(() => ({
    anyInitialLoading: false,
    preferences: { isLoading: false, data: { language: 'ru', timezone: 'UTC' } },
    consents: { isLoading: false, data: { consents: [] }, refetch: vi.fn() },
    sessions: { isLoading: false, data: { sessions: [] }, refetch: vi.fn() },
    apps: { isLoading: false, data: { items: [] }, refetch: vi.fn() },
    history: { isLoading: false, data: { events: [] } },
    mfa: { isLoading: false, data: { has_totp: false, has_webauthn: false, has_recovery_codes: false } },
    passkeys: { isLoading: false, data: { authenticators: [] }, refetch: vi.fn() },
    providers: { isLoading: false, data: { providers: [] } },
    timezones: { isLoading: false, data: { timezones: [] } },
    emailStatus: { isLoading: false, data: { email: 'u@example.com', verified: true }, refetch: vi.fn() },
  })),
}));

describe('AccountPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('saves profile through API from profile section', async () => {
    render(
      <MemoryRouter>
        <AuthContext.Provider
          value={{
            user: {
              id: 'u1',
              email: 'u@example.com',
              first_name: 'User',
              last_name: 'One',
              email_verified: true,
            },
            loading: false,
            refresh: vi.fn(),
            login: vi.fn(),
            signup: vi.fn(),
            logout: vi.fn(),
          }}
        >
          <I18nProvider>
            <AccountPage />
          </I18nProvider>
        </AuthContext.Provider>
      </MemoryRouter>,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }));

    expect(api.updateProfile).toHaveBeenCalledTimes(1);
    expect(api.updateProfile).toHaveBeenCalledWith({
      first_name: 'User',
      last_name: 'One',
      phone_number: '',
      birth_date: '',
    });
  });
});
