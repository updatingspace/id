import { expect, test } from '@playwright/test';

test('guest can request a recovery email from login', async ({ page }) => {
  await page.route('**/api/v1/auth/oauth/providers', (route) => route.fulfill({ json: { providers: [] } }));
  await page.route('**/api/v1/auth/form_token?purpose=password_reset', (route) => route.fulfill({ json: { form_token: 'form-key', expires_in: 900 } }));
  await page.route('**/api/v1/auth/password/reset/request', async (route) => {
    expect(route.request().postDataJSON()).toEqual({ email: 'recover@example.com', form_token: 'form-key' });
    await route.fulfill({ json: { ok: true } });
  });
  await page.goto('/login');
  await page.getByRole('link', { name: 'Забыли пароль?' }).click();
  await expect(page.getByRole('heading', { name: 'Восстановление доступа', exact: true })).toBeVisible();
  await page.getByLabel('Email').fill('recover@example.com');
  await page.getByRole('button', { name: 'Отправить письмо' }).click();
  await expect(page.getByRole('status')).toContainText('Если аккаунт с таким email существует');
  await page.screenshot({ path: '/tmp/id-recovery-desktop.png', fullPage: true });
});

test('email reset link sets a password and clears the key from the URL', async ({ page }) => {
  const urls: string[] = [];
  page.on('request', (request) => urls.push(request.url()));
  await page.route('**/api/v1/auth/password/reset/confirm', async (route) => {
    expect(route.request().postDataJSON()).toEqual({ key: '1-token-secret', password: 'NewStrongPassword123!' });
    await route.fulfill({ json: { ok: true } });
  });
  await page.route('**/api/v1/auth/logout', (route) => route.fulfill({ json: { ok: true } }));
  await page.goto('/reset-password#key=1-token-secret');
  await page.getByLabel('Новый пароль', { exact: true }).fill('NewStrongPassword123!');
  await page.getByLabel('Повторите новый пароль').fill('NewStrongPassword123!');
  await page.getByRole('button', { name: 'Сохранить пароль' }).click();
  await expect(page.getByRole('status')).toContainText('Пароль изменён');
  await expect(page).toHaveURL(/\/reset-password$/);
  expect(urls.some((url) => url.includes('1-token-secret'))).toBe(false);
});

test('confirmation link works on mobile and is not consumed on opening', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  let confirmations = 0;
  await page.route('**/api/v1/auth/email/verification/confirm', async (route) => {
    confirmations += 1;
    expect(route.request().postDataJSON()).toEqual({ key: 'signed:key' });
    await route.fulfill({ json: { ok: true } });
  });
  await page.goto('/verify-email#key=signed%3Akey');
  await expect(page.getByRole('button', { name: 'Подтвердить email' })).toBeVisible();
  expect(confirmations).toBe(0);
  await page.screenshot({ path: '/tmp/id-verification-mobile.png', fullPage: true });
  await page.getByRole('button', { name: 'Подтвердить email' }).click();
  await expect(page.getByRole('status')).toContainText('Email подтверждён');
  expect(confirmations).toBe(1);
});
