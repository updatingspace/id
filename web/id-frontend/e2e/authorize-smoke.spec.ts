import { expect, test } from '@playwright/test';

const authorizeQuery =
  '/authorize?client_id=portal&redirect_uri=http%3A%2F%2F127.0.0.1%3A4173%2Foauth-complete&response_type=code&scope=openid%20profile&state=s1';

test('authorize approve redirects to callback', async ({ page }) => {
  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      json: { user: { email: 'user@example.com', first_name: 'User' } },
    });
  });

  await page.route('**/oauth/authorize/prepare**', async (route) => {
    await route.fulfill({
      status: 200,
      json: {
        request_id: 'req-1',
        client: { client_id: 'portal', name: 'Portal' },
        scopes: [{ name: 'openid', description: 'OpenID', required: true, granted: true }],
        consent_required: false,
        redirect_uri: 'http://127.0.0.1:4173/oauth-complete',
      },
    });
  });

  await page.route('**/oauth/authorize/approve', async (route) => {
    await route.fulfill({
      status: 200,
      json: { redirect_uri: '/oauth-complete?code=ok' },
    });
  });

  await page.goto(authorizeQuery);
  await expect(page.getByText('Подтверждение входа')).toBeVisible();
  await page.getByRole('button', { name: 'Продолжить' }).click();

  await expect(page).toHaveURL('http://127.0.0.1:4173/oauth-complete?code=ok');
});

test('authorize deny redirects with access_denied', async ({ page }) => {
  await page.route('**/api/v1/auth/me', async (route) => {
    await route.fulfill({
      status: 200,
      json: { user: { email: 'user@example.com', first_name: 'User' } },
    });
  });

  await page.route('**/oauth/authorize/prepare**', async (route) => {
    await route.fulfill({
      status: 200,
      json: {
        request_id: 'req-2',
        client: { client_id: 'portal', name: 'Portal' },
        scopes: [{ name: 'openid', description: 'OpenID', required: true, granted: true }],
        consent_required: false,
        redirect_uri: 'http://127.0.0.1:4173/oauth-complete',
      },
    });
  });

  await page.route('**/oauth/authorize/deny', async (route) => {
    await route.fulfill({
      status: 200,
      json: { redirect_uri: '/oauth-complete?error=access_denied' },
    });
  });

  await page.goto(authorizeQuery);
  await expect(page.getByText('Подтверждение входа')).toBeVisible();
  await page.getByRole('button', { name: 'Отклонить' }).click();

  await expect(page).toHaveURL('http://127.0.0.1:4173/oauth-complete?error=access_denied');
});
