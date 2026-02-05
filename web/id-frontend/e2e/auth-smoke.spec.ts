import { expect, test } from '@playwright/test';

test('login success flow redirects to next path', async ({ page }) => {
  let loggedIn = false;

  await page.route('**/api/v1/auth/oauth/providers', async (route) => {
    await route.fulfill({ status: 200, json: { providers: [] } });
  });

  await page.route('**/api/v1/auth/login', async (route) => {
    loggedIn = true;
    await route.fulfill({
      status: 200,
      json: {
        meta: { session_token: 'session-1' },
        user: { email: 'user@example.com' },
      },
    });
  });

  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      json: {
        user: loggedIn ? { email: 'user@example.com', first_name: 'User' } : null,
      },
    });
  });

  await page.goto('/login?next=/');
  await page.getByLabel('Email').fill('user@example.com');
  await page.getByLabel('Пароль').fill('StrongPass123!');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();

  await expect(page).toHaveURL('http://127.0.0.1:4173/');
});

test('login failure shows translated error', async ({ page }) => {
  await page.route('**/api/v1/auth/oauth/providers', async (route) => {
    await route.fulfill({ status: 200, json: { providers: [] } });
  });

  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill({ status: 200, json: { user: null } });
  });

  await page.route('**/api/v1/auth/login', async (route) => {
    await route.fulfill({
      status: 401,
      json: { code: 'INVALID_CREDENTIALS', message: 'bad credentials' },
    });
  });

  await page.goto('/login');
  await page.getByLabel('Email').fill('user@example.com');
  await page.getByLabel('Пароль').fill('WrongPass!');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();

  await expect(page.getByText('Неверный email или пароль')).toBeVisible();
});
