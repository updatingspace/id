// Real Chromium -> Topcoat -> Rust API -> local YDB operator journey.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const playwrightPath = process.env.ID_PLAYWRIGHT_MODULE || path.resolve(__dirname, '../browser-tests/node_modules/@playwright/test');
const { chromium } = require(playwrightPath);

async function main() {
  const fixture = JSON.parse(fs.readFileSync(process.env.ID_ADMIN_BROWSER_FIXTURE_OUTPUT, 'utf8'));
  assert.equal(fixture.synthetic, true);
  assert.equal(fixture.format_version, 1);
  const origin = process.env.ID_LIVE_BASE_URL;
  const browser = await chromium.launch({ headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}) });
  try {
    const context = await browser.newContext();
    await context.addCookies([
      { name: 'sessionid', value: fixture.session_token, url: origin, sameSite: 'Lax' },
      { name: 'csrftoken', value: 'abcdefghijklmnopqrstuvwxyzABCDEF', url: origin, sameSite: 'Lax' },
    ]);
    for (const width of [320, 390, 1280]) {
      const page = await context.newPage({ viewport: { width, height: 820 } });
      const deletion = await page.goto(`${origin}/admin/?deletion=${fixture.deletion_id}`);
      assert.equal(deletion.status(), 200);
      assert.equal(deletion.headers()['cache-control'], 'no-store');
      assert.match(await page.locator('main').innerText(), /Ожидает обработки/);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      if (width === 390) {
        await page.emulateMedia({ colorScheme: 'dark' });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        await page.emulateMedia({ colorScheme: 'light' });
      }
      const account = await page.goto(`${origin}/admin/accounts/?id=${fixture.target_id}`);
      assert.equal(account.status(), 200);
      assert.match(await page.locator('main').innerText(), /Доступен/);
      assert.equal(await page.getByRole('link', { name: /блокировки входа/ }).isVisible(), true);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await page.close();
    }
    const page = await context.newPage();
    await page.goto(`${origin}/admin/accounts/`);
    await page.locator('#account-email').fill(fixture.target_email);
    await page.getByRole('button', { name: 'Найти по почте' }).click();
    assert.match(await page.locator('main').innerText(), new RegExp(`Аккаунт № ${fixture.target_id}`));
    assert.equal(new URL(page.url()).searchParams.has('email'), false, 'email leaked into URL');
    await page.goto(`${origin}/admin/accounts/suspend?id=${fixture.target_id}`);
    await page.locator('#suspend-reason').selectOption('security_incident');
    await page.locator('#operator-password').fill('incorrect');
    await page.getByRole('button', { name: /Заблокировать вход/ }).click();
    await page.locator('#suspend-result:not([hidden])').waitFor();
    assert.match(await page.locator('#suspend-result').innerText(), /пароль/);
    assert.equal(await page.locator('#operator-password').inputValue(), '');
    await page.locator('#operator-password').fill(fixture.operator_password);
    await page.getByRole('button', { name: /Заблокировать вход/ }).click();
    await page.locator('#suspend-result:not([hidden])').waitFor();
    assert.match(await page.locator('#suspend-result').innerText(), /Вход заблокирован/);
    assert.equal(await page.locator('#suspend-form').isHidden(), true);
    const state = await context.request.get(`${origin}/api/v1/auth/admin/accounts/${fixture.target_id}`);
    assert.equal(state.status(), 200);
    assert.equal((await state.json()).account.access_state, 'account_disabled');
    console.log('PASS: real Chromium, Topcoat, Rust API and YDB operator journey at 320/390/1280 px');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
