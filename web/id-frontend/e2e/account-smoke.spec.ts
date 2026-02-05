import { expect, test } from '@playwright/test';

test('account profile save sends update request', async ({ page }) => {
  let profilePatchBody: unknown = null;

  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      json: {
        user: {
          id: 'u-1',
          email: 'user@example.com',
          first_name: 'User',
          last_name: 'One',
          email_verified: true,
        },
      },
    });
  });

  await page.route('**/api/v1/auth/profile', async (route) => {
    if (route.request().method() === 'PATCH') {
      profilePatchBody = route.request().postDataJSON();
    }
    await route.fulfill({ status: 200, json: { ok: true } });
  });

  await page.route('**/api/v1/auth/preferences', async (route) => {
    await route.fulfill({ status: 200, json: { language: 'ru', timezone: 'UTC' } });
  });
  await page.route('**/api/v1/auth/consents', async (route) => {
    await route.fulfill({ status: 200, json: { consents: [] } });
  });
  await page.route('**/api/v1/auth/sessions', async (route) => {
    await route.fulfill({ status: 200, json: { sessions: [] } });
  });
  await page.route('**/api/v1/auth/oauth/apps', async (route) => {
    await route.fulfill({ status: 200, json: { items: [] } });
  });
  await page.route('**/api/v1/auth/login-history', async (route) => {
    await route.fulfill({ status: 200, json: { events: [] } });
  });
  await page.route('**/api/v1/auth/mfa/status', async (route) => {
    await route.fulfill({
      status: 200,
      json: {
        has_totp: false,
        has_webauthn: false,
        has_recovery_codes: false,
        recovery_codes_left: 0,
      },
    });
  });
  await page.route('**/api/v1/auth/passkeys', async (route) => {
    await route.fulfill({ status: 200, json: { authenticators: [] } });
  });
  await page.route('**/api/v1/auth/oauth/providers', async (route) => {
    await route.fulfill({ status: 200, json: { providers: [] } });
  });
  await page.route('**/api/v1/auth/timezones', async (route) => {
    await route.fulfill({ status: 200, json: { timezones: [] } });
  });
  await page.route('**/api/v1/auth/email', async (route) => {
    await route.fulfill({
      status: 200,
      json: { email: 'user@example.com', verified: true },
    });
  });

  await page.goto('/account');
  await expect(page.getByText('Личный кабинет')).toBeVisible();
  await page.getByRole('button', { name: 'Сохранить' }).click();

  await expect
    .poll(() => profilePatchBody, { timeout: 8_000 })
    .not.toBeNull();
});
