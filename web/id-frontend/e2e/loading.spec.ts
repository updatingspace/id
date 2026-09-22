import { expect, test } from '@playwright/test';

test('guest login is usable without a session request or account chunk', async ({ page }) => {
  const requests: string[] = [];
  page.on('request', (request) => requests.push(request.url()));
  await page.route('**/api/v1/auth/oauth/providers', (route) => route.fulfill({ json: { providers: [] } }));
  await page.goto('/login');
  await expect(page.getByLabel('Email')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Войти', exact: true })).toBeEnabled();
  expect(requests.some((url) => url.includes('/auth/me'))).toBe(false);
  expect(requests.some((url) => url.includes('/assets/Account'))).toBe(false);
});

test('a pending session check does not hide the public login form', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('id_session_token', 'session-1'));
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/v1/auth/me', async (route) => {
    await pending;
    await route.fulfill({ json: { user: null } });
  });
  await page.route('**/api/v1/auth/oauth/providers', (route) => route.fulfill({ json: { providers: [] } }));
  try {
    await page.goto('/login');
    await expect(page.getByLabel('Email')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Войти', exact: true })).toBeEnabled();
  } finally { release(); }
});

test('a failed session check keeps a protected route closed until retry succeeds', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('id_session_token', 'session-1'));
  let calls = 0;
  await page.route('**/api/v1/auth/me', async (route) => {
    calls += 1;
    await route.fulfill(calls === 1
      ? { status: 503, json: { error: { code: 'SERVER_ERROR' } } }
      : { json: { user: { email: 'user@example.com', email_verified: true } } });
  });
  await page.route('**/api/v1/auth/email', (route) => route.fulfill({ json: { email: 'user@example.com', verified: true } }));
  await page.goto('/account');
  await expect(page.getByRole('alert')).toContainText('Не удалось проверить сессию');
  await expect(page.getByText('Личный кабинет')).not.toBeVisible();
  await expect(page).toHaveURL(/\/account$/);
  await page.getByRole('button', { name: 'Повторить', exact: true }).click();
  await expect(page.getByText('Личный кабинет')).toBeVisible();
  expect(calls).toBe(2);
});

test('expired session redirects to login preserving the OIDC request', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('id_session_token', 'expired'));
  await page.route('**/api/v1/auth/me', (route) => route.fulfill({ status: 401, json: { error: { code: 'INVALID_OR_EXPIRED_TOKEN' } } }));
  await page.route('**/api/v1/auth/oauth/providers', (route) => route.fulfill({ json: { providers: [] } }));
  const target = '/authorize?client_id=portal&state=keep-me';
  await page.goto(target);
  await expect(page.getByLabel('Email')).toBeVisible();
  expect(new URL(page.url()).searchParams.get('next')).toBe(target);
});

test('account navigation remains available while profile data is pending', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('id_session_token', 'session-1'));
  await page.route('**/api/v1/auth/me', (route) => route.fulfill({ json: { user: { email: 'user@example.com' } } }));
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route('**/api/v1/auth/email', async (route) => {
    await pending;
    await route.fulfill({ json: { email: 'user@example.com', verified: true } });
  });
  const sessionRequests: string[] = [];
  await page.route('**/api/v1/auth/sessions', (route) => {
    sessionRequests.push('sessions');
    return route.fulfill({ json: { sessions: [] } });
  });
  await page.route('**/api/v1/auth/login-history', (route) => route.fulfill({ json: { events: [] } }));
  try {
    await page.goto('/account');
    await expect(page.getByRole('button', { name: 'Сессии', exact: true })).toBeVisible();
    expect(sessionRequests).toEqual([]);
    await page.getByRole('button', { name: 'Сессии', exact: true }).click();
    await expect(page.getByText('Активные сессии', { exact: true })).toBeVisible();
    expect(sessionRequests).toEqual(['sessions']);
  } finally { release(); }
});
