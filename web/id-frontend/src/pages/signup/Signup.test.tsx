import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import SignupPage from './SignupPage';
import { AuthContext } from '../../lib/auth';
import { I18nProvider } from '../../lib/i18n';

const renderPage = (signup = vi.fn().mockResolvedValue({ ok: true })) => {
  render(
    <MemoryRouter>
      <AuthContext.Provider
        value={{
          user: null,
          loading: false,
          refresh: vi.fn(),
          login: vi.fn(),
          signup,
          logout: vi.fn(),
        }}
      >
        <I18nProvider>
          <SignupPage />
        </I18nProvider>
      </AuthContext.Provider>
    </MemoryRouter>,
  );
  return { signup };
};

describe('SignupPage', () => {
  it('keeps submit button disabled until consent to data processing is checked', async () => {
    renderPage();
    const submit = screen.getByRole('button', { name: 'Зарегистрироваться' });
    expect(submit).toBeDisabled();

    await userEvent.click(screen.getByLabelText('Согласие на обработку данных'));
    expect(submit).toBeEnabled();
  });

  it('shows translated backend error on failed signup', async () => {
    const signup = vi.fn().mockResolvedValue({ ok: false, code: 'SERVER_ERROR', message: 'boom' });
    renderPage(signup);

    await userEvent.type(screen.getByLabelText('Email'), 'new@example.com');
    await userEvent.type(screen.getByLabelText('Пароль'), 'super-secret');
    await userEvent.click(screen.getByLabelText('Согласие на обработку данных'));
    await userEvent.click(screen.getByRole('button', { name: 'Зарегистрироваться' }));

    expect(await screen.findByText('Ошибка сервера')).toBeInTheDocument();
    expect(signup).toHaveBeenCalledTimes(1);
  });
});
