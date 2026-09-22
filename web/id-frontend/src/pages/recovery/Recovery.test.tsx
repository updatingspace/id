import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { api } from '../../lib/api';
import { AuthContext } from '../../lib/auth';
import { I18nProvider } from '../../lib/i18n';
import ForgotPasswordPage from './ForgotPasswordPage';
import ResetPasswordPage from './ResetPasswordPage';
import VerifyEmailPage from './VerifyEmailPage';

vi.mock('../../lib/api', () => ({ api: {
  requestPasswordReset: vi.fn(), resetPassword: vi.fn(),
  requestEmailVerification: vi.fn(), confirmEmail: vi.fn(),
} }));

const logout = vi.fn().mockResolvedValue(undefined);
const show = (page: React.ReactNode, path = '/') => render(
  <MemoryRouter initialEntries={[path]}>
    <AuthContext.Provider value={{ user: null, loading: false, login: vi.fn(), signup: vi.fn(), logout, refresh: vi.fn() }}>
      <I18nProvider>{page}</I18nProvider>
    </AuthContext.Provider>
  </MemoryRouter>,
);

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.requestPasswordReset).mockResolvedValue({ ok: true });
  vi.mocked(api.resetPassword).mockResolvedValue({ ok: true });
  vi.mocked(api.requestEmailVerification).mockResolvedValue({ ok: true });
  vi.mocked(api.confirmEmail).mockResolvedValue({ ok: true });
});

describe('recovery', () => {
  it('requests a reset without login and shows a neutral confirmation', async () => {
    show(<ForgotPasswordPage />);
    await userEvent.type(screen.getByLabelText('Email'), 'recover@example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Отправить письмо' }));
    expect(api.requestPasswordReset).toHaveBeenCalledWith('recover@example.com');
    expect(await screen.findByRole('status')).toHaveTextContent('Если аккаунт с таким email существует');
  });

  it('shows rate limiting and allows retrying after a network failure', async () => {
    vi.mocked(api.requestPasswordReset).mockRejectedValueOnce({ code: 'RECOVERY_RATE_LIMITED' });
    show(<ForgotPasswordPage />);
    await userEvent.type(screen.getByLabelText('Email'), 'recover@example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Отправить письмо' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Слишком много запросов');
    await userEvent.click(screen.getByRole('button', { name: 'Отправить письмо' }));
    expect(await screen.findByRole('status')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('disables duplicate submissions while sending', async () => {
    let finish!: (result: { ok: boolean }) => void;
    vi.mocked(api.requestPasswordReset).mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    show(<ForgotPasswordPage />);
    await userEvent.type(screen.getByLabelText('Email'), 'recover@example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Отправить письмо' }));
    expect(screen.getByRole('button', { name: 'Отправляем…' })).toBeDisabled();
    finish({ ok: true });
    expect(await screen.findByRole('status')).toBeInTheDocument();
  });

  it('validates password confirmation and submits the fragment key', async () => {
    show(<ResetPasswordPage />, '/reset-password#key=1-abc-def');
    await userEvent.type(screen.getByLabelText('Новый пароль'), 'NewStrongPassword123!');
    await userEvent.type(screen.getByLabelText('Повторите новый пароль'), 'different');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить пароль' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Пароли не совпадают');
    expect(api.resetPassword).not.toHaveBeenCalled();
    await userEvent.clear(screen.getByLabelText('Повторите новый пароль'));
    await userEvent.type(screen.getByLabelText('Повторите новый пароль'), 'NewStrongPassword123!');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить пароль' }));
    expect(api.resetPassword).toHaveBeenCalledWith('1-abc-def', 'NewStrongPassword123!');
    expect(await screen.findByRole('status')).toHaveTextContent('Пароль изменён');
    expect(logout).toHaveBeenCalledOnce();
    expect(screen.queryByLabelText('Новый пароль')).not.toBeInTheDocument();
  });

  it('does not submit a reset without a key', () => {
    show(<ResetPasswordPage />);
    expect(screen.getByRole('alert')).toHaveTextContent('Ссылка недействительна');
    expect(screen.getByRole('link', { name: 'Запросить новую ссылку' })).toHaveAttribute('href', '/forgot-password');
    expect(api.resetPassword).not.toHaveBeenCalled();
  });

  it('shows an expired reset link error', async () => {
    vi.mocked(api.resetPassword).mockRejectedValue({ code: 'INVALID_RECOVERY_LINK' });
    show(<ResetPasswordPage />, '/reset-password#key=expired');
    await userEvent.type(screen.getByLabelText('Новый пароль'), 'NewStrongPassword123!');
    await userEvent.type(screen.getByLabelText('Повторите новый пароль'), 'NewStrongPassword123!');
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить пароль' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Запросите новое письмо');
    expect(logout).not.toHaveBeenCalled();
  });

  it('waits for an explicit click before verifying an email link', async () => {
    show(<VerifyEmailPage />, '/verify-email#key=signed%3Akey');
    expect(api.confirmEmail).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Подтвердить email' }));
    expect(api.confirmEmail).toHaveBeenCalledWith('signed:key');
    expect(await screen.findByRole('status')).toHaveTextContent('Email подтверждён');
  });

  it('offers a new verification email when the old link has expired', async () => {
    vi.mocked(api.confirmEmail).mockRejectedValue({ code: 'INVALID_RECOVERY_LINK' });
    show(<VerifyEmailPage />, '/verify-email#key=expired');
    await userEvent.click(screen.getByRole('button', { name: 'Подтвердить email' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Запросите новое письмо');
    await userEvent.type(screen.getByLabelText('Email'), 'recover@example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Отправить письмо' }));
    expect(api.requestEmailVerification).toHaveBeenCalledWith('recover@example.com');
    expect(await screen.findByRole('status')).toHaveTextContent('Если адрес ожидает подтверждения');
  });
});
