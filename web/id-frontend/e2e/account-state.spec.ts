import { expect, test, type Page } from '@playwright/test';

async function account(page: Page) {
  await page.addInitScript(() => sessionStorage.setItem('id_session_token', 'account-state-test'));
  const state = {
    preferences: { language: 'ru', timezone: 'UTC', marketing_opt_in: true },
    mfa: { has_totp: false, has_webauthn: false, has_recovery_codes: false, recovery_codes_left: 0 },
    consents: [{ kind: 'marketing', granted_at: '2026-09-01', revoked_at: null as string | null }],
    passkeys: [] as { id: string; name: string }[],
    failSessions: false,
    failMutation: false,
    calls: [] as string[],
  };
  await page.route('**/api/v1/auth/**', async (route) => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1/auth/', '');
    const method = route.request().method();
    state.calls.push(`${method} ${path}`);
    if ((path === 'sessions' && state.failSessions) || (method !== 'GET' && state.failMutation)) {
      await route.fulfill({ status: 503, json: { error: { code: 'TEMPORARILY_UNAVAILABLE', message: 'Попробуйте позже' } } });
      return;
    }
    const reads: Record<string, unknown> = {
      me: { user: { id: 'account-state-user', email: 'account@example.invalid', first_name: 'Test', email_verified: true } },
      email: { email: 'account@example.invalid', verified: true },
      preferences: state.preferences,
      consents: { consents: state.consents },
      sessions: { sessions: [{ id: 's2', user_agent: 'Other device' }] },
      'login-history': { events: [] },
      'mfa/status': state.mfa,
      passkeys: { authenticators: state.passkeys },
      'oauth/providers': { providers: [] },
      'oauth/apps': { items: [{ client_id: 'portal', name: 'Portal', scopes: ['openid'] }] },
      timezones: { timezones: [{ name: 'UTC', display_name: 'UTC', offset: '+00:00' }, { name: 'Europe/Moscow', display_name: 'Moscow', offset: '+03:00' }] },
    };
    if (method === 'GET' && path in reads) {
      await route.fulfill({ json: reads[path] });
      return;
    }
    if (path === 'preferences' && method === 'PATCH') {
      Object.assign(state.preferences, route.request().postDataJSON());
      await route.fulfill({ json: state.preferences });
      return;
    }
    if (path === 'consents/revoke') {
      state.preferences.marketing_opt_in = false;
      state.consents[0].revoked_at = '2026-09-23';
    } else if (path === 'mfa/totp/begin') {
      await route.fulfill({ json: { secret: 'test-secret', svg_data_uri: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"/>' } });
      return;
    } else if (path === 'mfa/totp/confirm') {
      state.mfa.has_totp = true;
    } else if (path === 'mfa/totp/disable') {
      state.mfa.has_totp = false;
    } else if (path === 'passkeys/delete') {
      state.passkeys = [];
      state.mfa.has_webauthn = false;
    }
    await route.fulfill({ json: { ok: true } });
  });
  await page.goto('/account');
  await expect(page.getByRole('button', { name: 'Сохранить', exact: true })).toBeVisible();
  return state;
}

const tab = (page: Page, name: string) => page.getByRole('button', { name, exact: true }).click();

test('failed session reads show a recoverable error rather than empty account data', async ({ page }) => {
  const state = await account(page);
  state.failSessions = true;
  await tab(page, 'Сессии');
  await expect(page.getByRole('alert')).toBeVisible();
  state.failSessions = false;
  await page.getByRole('button', { name: 'Повторить' }).click();
  await expect(page.getByText('Other device')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
});

test('saved preferences survive tab navigation without a second preferences read', async ({ page }) => {
  const state = await account(page);
  await tab(page, 'Приватность');
  await page.getByLabel('Часовой пояс').selectOption('Europe/Moscow');
  await page.getByRole('button', { name: 'Сохранить настройки', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('Предпочтения обновлены');
  await tab(page, 'Профиль');
  await tab(page, 'Приватность');
  await expect(page.getByLabel('Часовой пояс')).toHaveValue('Europe/Moscow');
  expect(state.calls.filter((call) => call === 'GET preferences')).toHaveLength(1);
});

test('revoking marketing updates both consent and an edited preferences draft', async ({ page }) => {
  await account(page);
  await tab(page, 'Приватность');
  await page.getByLabel('Часовой пояс').selectOption('Europe/Moscow');
  await page.getByRole('button', { name: 'Отозвать', exact: true }).click();
  await expect(page.getByText('Отозвано', { exact: true })).toBeVisible();
  await expect(page.getByRole('checkbox')).not.toBeChecked();
  await expect(page.getByLabel('Часовой пояс')).toHaveValue('Europe/Moscow');
});

test('TOTP confirmation and disabling update status and available actions immediately', async ({ page }) => {
  await account(page);
  await tab(page, 'Безопасность');
  await page.getByRole('button', { name: 'Включить 2FA', exact: true }).click();
  await page.getByLabel('Код MFA').fill('123456');
  await page.getByRole('button', { name: 'Подтвердить 2FA', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Отключить 2FA', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Отключить 2FA', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Включить 2FA', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Обновить recovery-коды' })).toBeDisabled();
});

test('deleting the last passkey refreshes MFA and the data export requirements', async ({ page }) => {
  const state = await account(page);
  state.passkeys = [{ id: 'pk1', name: 'Test key' }];
  state.mfa.has_webauthn = true;
  await tab(page, 'Безопасность');
  await page.getByRole('button', { name: 'Удалить', exact: true }).click();
  await expect(page.getByText('Test key')).toHaveCount(0);
  await tab(page, 'Данные');
  await expect(page.getByLabel('Текущий пароль')).toBeVisible();
  await expect(page.getByLabel('Код MFA')).toHaveCount(0);
});

for (const [section, button] of [['Сессии', 'Завершить'], ['Приложения', 'Отозвать доступ']] as const) {
  test(`mutation failure in ${section} stays visible and allows retry`, async ({ page }) => {
    const errors: Error[] = [];
    page.on('pageerror', (error) => errors.push(error));
    const state = await account(page);
    state.failMutation = true;
    await tab(page, section);
    await page.getByRole('button', { name: button, exact: true }).click();
    await expect(page.getByRole('alert')).toHaveText('Попробуйте позже');
    await expect(page.getByRole('button', { name: button, exact: true })).toBeEnabled();
    state.failMutation = false;
    await page.getByRole('button', { name: button, exact: true }).click();
    await expect(page.getByRole('alert')).toHaveCount(0);
    expect(errors).toEqual([]);
  });
}

test('successful account deletion clears local authentication without a redundant logout request', async ({ page }) => {
  const state = await account(page);
  await tab(page, 'Данные');
  await page.getByLabel('Текущий пароль').fill('synthetic-test-password');
  page.on('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Удалить аккаунт', exact: true }).click();
  await expect(page).toHaveURL(/\/login(?:\?|$)/);
  expect(await page.evaluate(() => sessionStorage.getItem('id_session_token'))).toBeNull();
  await expect(page.getByRole('link', { name: 'Войти', exact: true })).toBeVisible();
  expect(state.calls).not.toContain('POST logout');
});

test('profile save cannot be submitted twice while its request is pending', async ({ page }) => {
  await account(page);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  let requests = 0;
  await page.route('**/api/v1/auth/profile', async (route) => {
    requests += 1;
    await pending;
    await route.fulfill({ json: { ok: true } });
  });
  const save = page.getByRole('button', { name: 'Сохранить', exact: true });
  await save.click();
  await expect(save).toBeDisabled();
  release();
  await expect(page.getByRole('status')).toHaveText('Профиль обновлён');
  await expect(save).toBeEnabled();
  expect(requests).toBe(1);
});
