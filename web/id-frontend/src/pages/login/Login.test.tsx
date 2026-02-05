import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import LoginPage from './LoginPage';
import { AuthContext } from '../../lib/auth';
import { I18nProvider } from '../../lib/i18n';

vi.mock('../lib/api', () => ({
  api: {
    getOAuthProviders: vi.fn().mockResolvedValue({ providers: [] }),
    getOAuthLoginUrl: vi.fn(),
    passkeyLoginBegin: vi.fn(),
    passkeyLoginComplete: vi.fn(),
  },
}));

describe('LoginPage', () => {
  it('shows an error when credentials are invalid', async () => {
    const mockLogin = vi
      .fn()
      .mockResolvedValue({ ok: false, code: 'INVALID_CREDENTIALS', message: 'Bad credentials' });
    render(
      <MemoryRouter>
        <AuthContext.Provider
          value={{
            user: null,
            loading: false,
            refresh: vi.fn(),
            login: mockLogin,
            signup: vi.fn(),
            logout: vi.fn(),
          }}
        >
          <I18nProvider>
            <LoginPage />
          </I18nProvider>
        </AuthContext.Provider>
      </MemoryRouter>,
    );

    await userEvent.type(screen.getByLabelText(/Email/i), 'test@example.com');
    await userEvent.type(screen.getByLabelText(/Пароль/i), 'secret');
    await userEvent.click(screen.getByRole('button', { name: /^Войти$/ }));

    expect(await screen.findByText('Неверный email или пароль')).toBeInTheDocument();
    expect(mockLogin).toHaveBeenCalledWith('test@example.com', 'secret', '', undefined);
  });
});
