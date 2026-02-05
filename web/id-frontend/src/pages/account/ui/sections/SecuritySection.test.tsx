import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SecuritySection } from './SecuritySection';

const t = (k: string) => k;

const baseProps = {
  t,
  user: { oauth_providers: [] },
  emailVerified: true,
  mfaStatus: { has_totp: false, has_webauthn: false, has_recovery_codes: false, recovery_codes_left: 0 },
  passkeys: [],
  providers: [{ id: 'google', name: 'Google' }],
  requiresMfa: false,
  onChangePassword: vi.fn().mockResolvedValue(undefined),
  onEnableTotp: vi.fn().mockResolvedValue({
    secret: 'secret',
    otpauth_url: 'otpauth://totp/test',
    svg: '<svg />',
    svg_data_uri: 'data:image/svg+xml;base64,abc',
  }),
  onConfirmTotp: vi.fn().mockResolvedValue({}),
  onDisableTotp: vi.fn().mockResolvedValue(undefined),
  onRegenRecovery: vi.fn().mockResolvedValue({ recovery_codes: ['one', 'two'] }),
  onAddPasskey: vi.fn().mockResolvedValue(undefined),
  onDeletePasskey: vi.fn().mockResolvedValue(undefined),
  onLinkProvider: vi.fn().mockResolvedValue({ authorize_url: 'https://oauth.example', method: 'GET' }),
  onUnlinkProvider: vi.fn().mockResolvedValue(undefined),
  setMessage: vi.fn(),
  setError: vi.fn(),
};

describe('SecuritySection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('starts and confirms TOTP flow', async () => {
    const confirm = vi.fn().mockResolvedValue({ recovery_codes: ['r1', 'r2'] });
    const alertSpy = vi.fn();
    vi.stubGlobal('alert', alertSpy);

    render(
      <SecuritySection
        {...baseProps}
        onConfirmTotp={confirm}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'security.totp.enable' }));
    expect(baseProps.onEnableTotp).toHaveBeenCalledTimes(1);

    await userEvent.type(screen.getByLabelText('login.mfa'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Подтвердить 2FA' }));

    await waitFor(() => {
      expect(confirm).toHaveBeenCalledWith('123456');
      expect(baseProps.setMessage).toHaveBeenCalledWith('2FA включена');
      expect(alertSpy).toHaveBeenCalledTimes(1);
    });
  });

  it('redirects via location.assign for GET provider linking', async () => {
    const assign = vi.fn();
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign },
      writable: true,
    });

    render(<SecuritySection {...baseProps} />);

    await userEvent.click(screen.getByRole('button', { name: 'security.providers.link' }));

    await waitFor(() => {
      expect(baseProps.onLinkProvider).toHaveBeenCalledWith('google');
      expect(assign).toHaveBeenCalledWith('https://oauth.example');
    });
  });
});
