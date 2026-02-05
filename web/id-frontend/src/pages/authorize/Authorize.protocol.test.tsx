import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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

describe('Authorize protocol behavior', () => {
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

  it('uses request_id from prepare payload when denying authorization', async () => {
    vi.mocked(api.oidcPrepare).mockResolvedValue({
      request_id: 'req-deny-1',
      client: { client_id: 'portal', name: 'Portal' },
      scopes: [{ name: 'openid', description: 'OpenID', required: true, granted: true }],
      consent_required: false,
      redirect_uri: 'https://client.local/callback',
    });
    vi.mocked(api.oidcDeny).mockResolvedValue({
      redirect_uri: 'https://client.local/callback?error=access_denied',
    });

    render(
      <MemoryRouter
        initialEntries={[
          '/authorize?client_id=portal&redirect_uri=https%3A%2F%2Fclient.local%2Fcallback&response_type=code&scope=openid',
        ]}
      >
        <AuthContext.Provider
          value={{
            user: { email: 'u@example.com' },
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
    await userEvent.click(screen.getByRole('button', { name: 'Отклонить' }));

    await waitFor(() => {
      expect(api.oidcDeny).toHaveBeenCalledWith('req-deny-1');
      expect(assignMock).toHaveBeenCalledWith('https://client.local/callback?error=access_denied');
    });
  });
});
