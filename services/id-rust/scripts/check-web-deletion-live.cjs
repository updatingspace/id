const assert = require('node:assert/strict');
const fs = require('node:fs');
const { chromium } = require(process.env.ID_PLAYWRIGHT_MODULE);

(async () => {
  const fixture = JSON.parse(fs.readFileSync(process.env.ID_DELETION_BROWSER_FIXTURE_OUTPUT, 'utf8'));
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? {executablePath: process.env.ID_CHROMIUM_PATH} : {}),
  });
  try {
    const context = await browser.newContext({viewport: {width: 375, height: 812}});
    await context.addCookies([{name: 'sessionid', value: fixture.session_token, domain: 'localhost', path: '/'}]);
    const page = await context.newPage();
    await page.goto(`${process.env.ID_LIVE_BASE_URL}/account?section=delete`);
    assert.match(await page.locator('main').innerText(), new RegExp(fixture.email, 'u'));
    await page.locator('#delete-password').fill(fixture.password);
    await page.locator('#delete-understood').check();
    await page.locator('.delete-button').click();
    await page.locator('#delete-result:visible').waitFor({timeout: 30000});
    const text = await page.locator('#delete-result').innerText();
    const match = text.match(/Запрос № ([1-9][0-9]{0,18}) принят/u);
    assert.ok(match, `missing real deletion receipt: ${text}`);
    fs.writeFileSync(process.env.ID_DELETION_BROWSER_RESULT, match[1]);
    const me = await context.request.get(`${process.env.ID_LIVE_BASE_URL}/api/v1/auth/me`);
    assert.equal(me.status(), 200);
    assert.equal((await me.json()).user, null, 'deleted account still has ID access');
    await page.goto(`${process.env.ID_LIVE_BASE_URL}/account`);
    assert.match(page.url(), /\/login\?next=%2Faccount/u);
    await context.close();
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
