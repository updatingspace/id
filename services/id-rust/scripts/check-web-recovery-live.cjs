// Chromium → Topcoat → Rust API → local YDB with a disposable account.
const assert = require('node:assert/strict');
const fs = require('node:fs');

const origin = process.env.ID_LIVE_BASE_URL;
const fixturePath = process.env.ID_RESET_BROWSER_FIXTURE_OUTPUT;
const keyPath = process.env.ID_RESET_BROWSER_KEY_OUTPUT;
const playwrightModule = process.env.ID_PLAYWRIGHT_MODULE;
if (!origin || !fixturePath || !keyPath || !playwrightModule) {
  console.error('Set ID_LIVE_BASE_URL, ID_RESET_BROWSER_FIXTURE_OUTPUT, ID_RESET_BROWSER_KEY_OUTPUT and ID_PLAYWRIGHT_MODULE');
  process.exit(2);
}
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
assert.equal(fixture.synthetic, true);
assert.equal(fixture.format_version, 1);
const { chromium } = require(playwrightModule);

async function waitForKey() {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (fs.existsSync(keyPath)) return fs.readFileSync(keyPath, 'utf8').trim();
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error('Reset intent did not appear in local YDB');
}

async function me(page) {
  return page.evaluate(async () => {
    const response = await fetch('/api/v1/auth/me', { credentials: 'include' });
    return { status: response.status, body: await response.json() };
  });
}

async function main() {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}),
  });
  try {
    const oldContext = await browser.newContext();
    await oldContext.addCookies([{
      name: 'sessionid', value: fixture.session_token, url: origin, httpOnly: true,
    }]);
    const oldPage = await oldContext.newPage();
    await oldPage.goto(origin + '/forgot-password');
    const before = await me(oldPage);
    assert.equal(before.status, 200, 'old browser session was not valid before reset');
    assert.equal(before.body.user.email, fixture.email);

    const context = await browser.newContext();
    const page = await context.newPage();
    const calls = [];
    page.on('response', response => {
      const path = new URL(response.url()).pathname;
      if (path.startsWith('/api/v1/auth/password/reset/')) calls.push([path, response.status()]);
    });
    await page.goto(origin + '/forgot-password');
    assert.equal(await page.locator('#forgot-form').isVisible(), true);
    await page.locator('#email').fill(fixture.email);
    await page.locator('#submit').click();
    await page.locator('#status').getByText('Если аккаунт с таким адресом существует', { exact: false }).waitFor();
    assert.deepEqual(calls, [['/api/v1/auth/password/reset/request', 200]]);
    const key = await waitForKey();
    assert.match(key, /^[0-9a-f-]+\.[A-Za-z0-9_-]+$/);

    // Open the emailed fragment in a fresh browser without any prior CSRF cookie.
    const resetContext = await browser.newContext();
    const reset = await resetContext.newPage();
    await reset.goto(origin + '/reset-password#key=' + encodeURIComponent(key));
    await reset.locator('#reset-form').waitFor({ state: 'visible' });
    assert.equal(new URL(reset.url()).hash, '', 'reset key remained in browser URL');
    await reset.locator('#password').fill('Some valid first password 123!');
    await reset.locator('#confirmation').fill('Different valid password 123!');
    await reset.locator('#submit').click();
    await reset.locator('#error').getByText('Пароли не совпадают.').waitFor();
    assert.equal(await reset.locator('#reset-form').isVisible(), true);
    await reset.locator('#password').fill(fixture.new_password);
    await reset.locator('#confirmation').fill(fixture.new_password);
    const confirmResponse = reset.waitForResponse(response =>
      new URL(response.url()).pathname === '/api/v1/auth/password/reset/confirm'
      && response.request().method() === 'POST');
    await reset.locator('#submit').click();
    assert.equal((await confirmResponse).status(), 200);
    await reset.waitForFunction(() =>
      (!document.getElementById('status').hidden && document.getElementById('status').textContent.includes('Пароль изменён.'))
      || !document.getElementById('error').hidden);
    assert.match(await reset.locator('#status').textContent(), /Пароль изменён\./,
      `Reset failed: ${await reset.locator('#error').textContent()} (${JSON.stringify(calls)})`);
    assert.equal(await reset.locator('#reset-form').isVisible(), false);
    assert((await resetContext.cookies(origin)).some(cookie => cookie.name === 'csrftoken'));
    const after = await me(oldPage);
    assert.equal(after.status, 200);
    assert.equal(after.body.user, null, 'old browser session survived reset');

    const replay = await resetContext.newPage();
    await replay.goto(origin + '/reset-password#key=' + encodeURIComponent(key));
    await replay.locator('#password').fill('Another valid password 123!');
    await replay.locator('#confirmation').fill('Another valid password 123!');
    const replayResponse = replay.waitForResponse(response =>
      new URL(response.url()).pathname === '/api/v1/auth/password/reset/confirm'
      && response.request().method() === 'POST');
    await replay.locator('#submit').click();
    const repeated = await replayResponse;
    assert.equal(repeated.status(), 400);
    assert.equal((await repeated.json()).code, 'INVALID_RECOVERY_LINK');
    await replay.locator('#error').waitFor({ state: 'visible' });
    assert.match(await replay.locator('#error').textContent(), /Ссылка недействительна/);
    assert.equal(new URL(replay.url()).hash, '');
    console.log('PASS: Chromium Topcoat recovery, fresh-browser CSRF, one-use link and old-session revocation');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
