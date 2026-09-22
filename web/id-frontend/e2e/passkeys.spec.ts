import { expect, test } from '@playwright/test';

test('registers a resident passkey and logs in using the browser WebAuthn API', async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  const user = { id: '1', email: 'passkey@example.com', username: 'passkey', email_verified: true };
  const registrationChallenge = Buffer.alloc(32, 1).toString('base64url');
  const loginChallenge = Buffer.alloc(32, 2).toString('base64url');
  let registered = false;
  let loginCompleted = false;
  await page.addInitScript(() => {
    if (!sessionStorage.getItem('passkey-test-seeded')) {
      sessionStorage.setItem('id_session_token', 'password-session');
      sessionStorage.setItem('passkey-test-seeded', 'yes');
    }
  });
  page.on('dialog', (dialog) => dialog.type() === 'prompt' ? dialog.accept('Browser passkey') : dialog.accept());
  await page.route('**/api/v1/auth/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown;
    if (path.endsWith('/passkeys/begin')) {
      expect(route.request().postDataJSON().passwordless).toBe(true);
      json = { creation_options: { publicKey: {
        rp: { id: 'localhost', name: 'UpdSpace ID' },
        user: { id: 'MQ', name: user.email, displayName: 'Passkey user' },
        challenge: registrationChallenge, pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        extensions: { credProps: true }, excludeCredentials: [],
      } } };
    } else if (path.endsWith('/passkeys/complete')) {
      const payload = route.request().postDataJSON();
      expect(payload.name).toBe('Browser passkey');
      expect(payload.credential.clientExtensionResults.credProps.rk).toBe(true);
      expect(payload.credential.response.transports).toContain('internal');
      const data = JSON.parse(Buffer.from(payload.credential.response.clientDataJSON, 'base64url').toString());
      expect(data.challenge).toBe(registrationChallenge);
      expect(data.type).toBe('webauthn.create');
      registered = true;
      json = { ok: true, recovery_codes: ['test-recovery-code'] };
    } else if (path.endsWith('/passkeys/login/begin')) {
      json = { request_options: { publicKey: {
        challenge: loginChallenge, rpId: 'localhost', userVerification: 'required',
      } } };
    } else if (path.endsWith('/passkeys/login/complete')) {
      const credential = route.request().postDataJSON().credential;
      const data = JSON.parse(Buffer.from(credential.response.clientDataJSON, 'base64url').toString());
      expect(data.challenge).toBe(loginChallenge);
      expect(data.type).toBe('webauthn.get');
      expect(credential.response.userHandle).toBe('MQ');
      expect(credential.response.signature).toBeTruthy();
      loginCompleted = true;
      json = { user, meta: { session_token: 'passkey-session' }, access_token: 'not-a-session-token' };
    } else if (path.endsWith('/me')) {
      json = { user };
    } else if (path.endsWith('/email')) {
      json = { email: user.email, verified: true };
    } else if (path.endsWith('/mfa/status')) {
      json = { has_totp: false, has_webauthn: registered, has_recovery_codes: registered };
    } else if (path.endsWith('/passkeys')) {
      json = { authenticators: registered ? [{ id: '1', name: 'Browser passkey', is_passwordless: true }] : [] };
    } else if (path.endsWith('/oauth/providers')) {
      json = { providers: [] };
    } else if (path.endsWith('/preferences')) {
      json = { language: 'ru', timezone: 'UTC' };
    } else {
      json = {};
    }
    await route.fulfill({ status: 200, json });
  });
  try {
    await page.goto('http://localhost:4173/account');
    await page.getByRole('button', { name: 'Безопасность', exact: true }).click();
    await page.getByRole('button', { name: 'Добавить Passkey', exact: true }).click();
    await expect(page.getByText('Passkey добавлен', { exact: true })).toBeVisible();
    expect(registered).toBe(true);
    const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
    expect(credentials.credentials).toHaveLength(1);
    expect(credentials.credentials[0].isResidentCredential).toBe(true);
    await page.evaluate(() => sessionStorage.removeItem('id_session_token'));
    await page.goto('http://localhost:4173/login');
    await page.getByRole('button', { name: 'Войти по Passkey', exact: true }).click();
    await expect(page).toHaveURL(/\/account$/);
    expect(loginCompleted).toBe(true);
    await expect.poll(() => page.evaluate(() => sessionStorage.getItem('id_session_token'))).toBe('passkey-session');
  } finally {
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
    await cdp.detach().catch(() => {});
  }
});
