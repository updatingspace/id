import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import AuthorizePage from './AuthorizePage';
import { api } from '../../lib/api';
import { AuthContext } from '../../lib/auth';
import { I18nProvider } from '../../lib/i18n';

vi.mock('../../lib/api', () => ({
  api: {
    oidcPrepare: vi.fn(),
    oidcApprove: vi.fn(),
    oidcDeny: vi.fn(),
  },
}));

describe('AuthorizePage', () => {
  const assignMock = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign: assignMock },
      writable: true,
    });
  });

  afterEach(() => {
    assignMock.mockReset();
  });

  it('loads prepare payload and renders confirm mode when consent is not required', async () => {
    vi.mocked(api.oidcPrepare).mockResolvedValue({
      request_id: 'req-1',
      client: { client_id: 'cli-1', name: 'Portal' },
      scopes: [
        { name: 'openid', description: 'OpenID', required: true, granted: true },
      ],
      consent_required: false,
      redirect_uri: 'https://app.local/callback',
    });
    vi.mocked(api.oidcApprove).mockResolvedValue({ redirect_uri: 'https://app.local/callback' });

    render(
      <MemoryRouter initialEntries={['/authorize?client_id=cli-1&scope=openid']}>
        <AuthContext.Provider
          value={{
            user: { email: 'u@example.com', first_name: 'U', last_name: 'S' },
            loading: false,
            refresh: vi.fn(),
            login: vi.fn(),
            signup: vi.fn(),
            logout: vi.fn(),
          }}
        >
          <I18nProvider>
            <AuthorizePage />
          </I18nProvider>
        </AuthContext.Provider>
      </MemoryRouter>,
    );

    expect(await screen.findByText('Подтверждение входа')).toBeInTheDocument();
    expect(api.oidcPrepare).toHaveBeenCalledWith({ client_id: 'cli-1', scope: 'openid' });

    await userEvent.click(screen.getByRole('button', { name: 'Продолжить' }));

    await waitFor(() => {
      expect(api.oidcApprove).toHaveBeenCalledTimes(1);
      expect(assignMock).toHaveBeenCalledWith('https://app.local/callback');
    });
  });
});
