import { expect, test } from '@playwright/test';

for (const [path, purpose] of [
  ['/login', 'login'],
  ['/signup', 'register'],
  ['/forgot-password', 'password_reset'],
  ['/verify-email', 'email_verification'],
] as const) {
  test(`${path} prepares a token on interaction without sending the form`, async ({ page }) => {
    const requests: string[] = [];
    await page.route('**/api/v1/auth/**', async (route) => {
      const request = route.request();
      requests.push(`${request.method()} ${new URL(request.url()).pathname}`);
      if (request.url().includes('/form_token')) {
        expect(new URL(request.url()).searchParams.get('purpose')).toBe(purpose);
        await route.fulfill({ json: { form_token: 'prepared', expires_in: 900 } });
      } else {
        await route.fulfill({ json: { providers: [] } });
      }
    });
    await page.goto(path);
    await expect(page.getByLabel('Email')).toBeVisible();
    expect(requests.some((request) => request.includes('form_token'))).toBe(false);
    const prepared = page.waitForResponse((response) => response.url().includes('/form_token'));
    await page.getByLabel('Email').fill('user@example.com');
    await prepared;
    await page.getByLabel('Email').fill('updated@example.com');
    expect(requests.filter((request) => request.includes('form_token'))).toHaveLength(1);
    expect(requests.some((request) => request.startsWith('POST'))).toBe(false);
  });
}

test('login submits a prepared token and obtains a new one for the MFA attempt', async ({ page }) => {
  let issued = 0;
  const submitted: string[] = [];
  await page.route('**/api/v1/auth/oauth/providers', (route) => route.fulfill({ json: { providers: [] } }));
  await page.route('**/api/v1/auth/form_token?purpose=login', (route) => {
    issued += 1;
    return route.fulfill({ json: { form_token: `token-${issued}`, expires_in: 900 } });
  });
  await page.route('**/api/v1/auth/login', (route) => {
    submitted.push(route.request().postDataJSON().form_token);
    return route.fulfill({ status: 401, json: { code: submitted.length === 1 ? 'MFA_REQUIRED' : 'INVALID_CREDENTIALS' } });
  });
  await page.goto('/login');
  const first = page.waitForResponse((response) => response.url().includes('/form_token'));
  await page.getByLabel('Email').fill('user@example.com');
  await first;
  await page.getByLabel('Пароль', { exact: true }).fill('test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page.getByLabel('Код MFA')).toBeVisible();
  expect(issued).toBe(1);
  expect(submitted).toEqual(['token-1']);

  const second = page.waitForResponse((response) => response.url().includes('/form_token'));
  await page.getByLabel('Код MFA').fill('123456');
  await second;
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page.getByText('Неверный email или пароль')).toBeVisible();
  expect(issued).toBe(2);
  expect(submitted).toEqual(['token-1', 'token-2']);
});

test('a failed preparation does not block the form or repeat the login POST', async ({ page }) => {
  let issued = 0;
  let logins = 0;
  await page.route('**/api/v1/auth/oauth/providers', (route) => route.fulfill({ json: { providers: [] } }));
  await page.route('**/api/v1/auth/form_token?purpose=login', (route) => {
    issued += 1;
    return route.fulfill(issued === 1
      ? { status: 503, json: { code: 'SERVER_ERROR' } }
      : { json: { form_token: 'fallback', expires_in: 900 } });
  });
  await page.route('**/api/v1/auth/login', (route) => {
    logins += 1;
    expect(route.request().postDataJSON().form_token).toBe('fallback');
    return route.fulfill({ status: 401, json: { code: 'INVALID_CREDENTIALS' } });
  });
  await page.goto('/login');
  const failed = page.waitForResponse((response) => response.url().includes('/form_token') && response.status() === 503);
  await page.getByLabel('Email').fill('user@example.com');
  await failed;
  await expect(page.getByRole('button', { name: 'Войти', exact: true })).toBeEnabled();
  await page.getByLabel('Пароль', { exact: true }).fill('test-password');
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  await expect(page.getByText('Неверный email или пароль')).toBeVisible();
  expect(issued).toBe(2);
  expect(logins).toBe(1);
});
