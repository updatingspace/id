// Chromium → Topcoat → Rust API → disposable local YDB.
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

const origin = process.env.ID_LIVE_BASE_URL;
const playwrightModule = process.env.ID_PLAYWRIGHT_MODULE;
if (!origin || !playwrightModule) {
  console.error('Set ID_LIVE_BASE_URL and ID_PLAYWRIGHT_MODULE');
  process.exit(2);
}
const { chromium } = require(playwrightModule);

async function main() {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}),
  });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const pageErrors = [];
    page.on('pageerror', error => pageErrors.push(error.message));
    const requests = [];
    page.on('response', response => {
      const path = new URL(response.url()).pathname;
      if (path === '/api/v1/auth/signup') requests.push(response.status());
    });
    const id = randomUUID().replaceAll('-', '');
    const email = `browser-signup-${id}@example.invalid`;
    const username = `browser-signup-${id}`;
    await page.goto(origin + '/signup?next=%2Faccount%3Fsection%3Dsecurity');
    assert.equal(await page.locator('#signup-form').isVisible(), true);
    assert.equal(await page.locator('.signup-card a[href^="/login"]').getAttribute('href'), '/login?next=%2Faccount%3Fsection%3Dsecurity');
    await page.locator('#is-minor').check();
    assert.equal(await page.locator('#guardian-fields').isVisible(), true);
    assert.equal(await page.locator('#guardian-email').getAttribute('required'), '');
    await page.locator('#is-minor').uncheck();
    assert.equal(await page.locator('#guardian-fields').isVisible(), false);
    await page.getByText('Дополнительные сведения', { exact: true }).click();
    await page.locator('#username').fill(username);
    await page.locator('#email').fill(email);
    await page.locator('#password').fill('A remarkable celestial phrase 2026!');
    await page.locator('#confirmation').fill('different password');
    await page.locator('#consent-data').check();
    await page.locator('#submit').click();
    await page.locator('#error').getByText('Пароли не совпадают.').waitFor();
    assert.deepEqual(requests, [], 'mismatched passwords reached the API');

    await page.locator('#confirmation').fill('A remarkable celestial phrase 2026!');
    const signup = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/signup');
    await page.locator('#submit').click();
    let response;
    try { response = await signup; }
    catch (cause) {
      const state = await page.evaluate(() => ({
        error: document.getElementById('error').textContent,
        status: document.getElementById('status').textContent,
        valid: document.getElementById('signup-form').checkValidity(),
        invalid: [...document.querySelectorAll('#signup-form :invalid')].map(item => item.id),
      }));
      throw new Error(`Signup did not reach API: ${JSON.stringify({ state, pageErrors })}`, { cause });
    }
    assert.equal(response.status(), 201, JSON.stringify(await response.json()));
    await page.locator('#status').getByText('Аккаунт создан.', { exact: false }).waitFor();
    assert.equal(await page.locator('#signup-form').isVisible(), false);
    assert.deepEqual(requests, [201]);
    assert(!(await context.cookies(origin)).some(cookie => cookie.name === 'sessionid'), 'signup issued session before email verification');
    const me = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/me', { credentials: 'include' });
      return { status: response.status, body: await response.json() };
    });
    assert.equal(me.status, 200);
    assert.equal(me.body.user, null, 'unverified account became authenticated');

    const duplicate = await context.newPage();
    await duplicate.goto(origin + '/signup');
    await duplicate.getByText('Дополнительные сведения', { exact: true }).click();
    await duplicate.locator('#username').fill(username + '-other');
    await duplicate.locator('#email').fill(email);
    await duplicate.locator('#password').fill('A remarkable celestial phrase 2026!');
    await duplicate.locator('#confirmation').fill('A remarkable celestial phrase 2026!');
    await duplicate.locator('#consent-data').check();
    const duplicateResponse = duplicate.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/signup');
    await duplicate.locator('#submit').click();
    const rejected = await duplicateResponse;
    const duplicateBody = await rejected.json();
    assert.equal(rejected.status(), 409, JSON.stringify(duplicateBody));
    assert.equal(duplicateBody.code, 'EMAIL_ALREADY_EXISTS');
    await duplicate.locator('#error').waitFor({ state: 'visible' });

    const minor = await context.newPage();
    await minor.goto(origin + '/signup');
    const born = new Date();
    born.setFullYear(born.getFullYear() - 17);
    await minor.getByText('Дополнительные сведения', { exact: true }).click();
    await minor.locator('#birth-date').fill(born.toISOString().slice(0, 10));
    assert.equal(await minor.locator('#guardian-fields').isVisible(), true);
    await minor.locator('#username').fill(`minor-${id}`);
    await minor.locator('#email').fill(`minor-${id}@example.invalid`);
    await minor.locator('#password').fill('A remarkable celestial phrase 2026!');
    await minor.locator('#confirmation').fill('A remarkable celestial phrase 2026!');
    await minor.locator('#guardian-email').fill(`guardian-${id}@example.invalid`);
    await minor.locator('#guardian-consent').check();
    await minor.locator('#consent-data').check();
    const minorResponse = minor.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/signup');
    await minor.locator('#submit').click();
    const accepted = await minorResponse;
    assert.equal(accepted.status(), 201, JSON.stringify(await accepted.json()));
    assert(!(await context.cookies(origin)).some(cookie => cookie.name === 'sessionid'), 'minor signup issued session before verification');
    console.log('PASS: Chromium Topcoat adult/minor signup, CSRF/form token, no pre-verification session, duplicate email');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
