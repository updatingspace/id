// Browser contract for the Topcoat signup form, using the real SSR and scripts.
const assert = require('node:assert/strict');

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
    await context.addCookies([{ name: 'csrftoken', value: 'signup-ui-test-csrf', url: origin }]);
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    let payload;
    await page.route('**/api/v1/auth/form_token?purpose=register', route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ form_token: 'signup-ui-test-token' }),
    }));
    await page.route('**/api/v1/auth/signup', async route => {
      payload = JSON.parse(route.request().postData());
      assert.equal(route.request().headers()['x-csrftoken'], 'signup-ui-test-csrf');
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({ verification_required: true }),
      });
    });

    await page.goto(origin + '/signup?next=%2Faccount%3Fsection%3Dsecurity');
    assert.equal(await page.locator('a[href^="/login"]').last().getAttribute('href'),
      '/login?next=%2Faccount%3Fsection%3Dsecurity');
    const born = new Date();
    born.setFullYear(born.getFullYear() - 17);
    await page.locator('#birth-date').fill(born.toISOString().slice(0, 10));
    assert.equal(await page.locator('#guardian-fields').isVisible(), true);
    await page.locator('#email').fill('signup-ui-test@example.invalid');
    await page.locator('#password').fill('A remarkable celestial phrase 2026!');
    await page.locator('#confirmation').fill('A remarkable celestial phrase 2026!');
    await page.locator('#guardian-email').fill('guardian@example.invalid');
    await page.locator('#guardian-consent').check();
    await page.locator('#consent-data').check();
    await page.locator('#submit').click();
    await page.locator('#status').getByText('Аккаунт создан.', { exact: false }).waitFor();
    assert.equal(payload.email, 'signup-ui-test@example.invalid');
    assert.equal(payload.username, undefined);
    assert.equal(payload.is_minor, true);
    assert.equal(payload.guardian_email, 'guardian@example.invalid');
    assert.equal(payload.guardian_consent, true);
    assert.equal(payload.birth_date, born.toISOString().slice(0, 10));
    assert.equal(payload.consent_data_processing, true);
    assert.equal(payload.form_token, 'signup-ui-test-token');
    assert.equal(await page.locator('#status a').getAttribute('href'),
      '/verify-email?next=%2Faccount%3Fsection%3Dsecurity');
    assert.deepEqual(errors, []);
    console.log('PASS: Topcoat signup browser fields, guardian consent, CSRF and return path');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
