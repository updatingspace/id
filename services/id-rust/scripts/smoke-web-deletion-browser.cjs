const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const testRequire = createRequire(path.join(process.env.ID_BROWSER_TEST_ROOT, 'package.json'));
const { chromium } = testRequire('@playwright/test');

(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.ID_BROWSER_CHROMIUM ? {executablePath: process.env.ID_BROWSER_CHROMIUM} : {}),
  });
  try {
    const context = await browser.newContext({ viewport: { width: 320, height: 700 } });
    await context.addCookies([{name: 'sessionid', value: 'valid', domain: '127.0.0.1', path: '/'}]);
    const page = await context.newPage();
    const url = `http://127.0.0.1:${process.env.ID_PILOT_WEB_PORT}/account?section=delete`;
    if (process.env.ID_BROWSER_SCREENSHOT_DIR) {
      await page.goto(`http://127.0.0.1:${process.env.ID_PILOT_WEB_PORT}/account`);
      await page.screenshot({path: path.join(process.env.ID_BROWSER_SCREENSHOT_DIR, 'account-mobile.png'), fullPage: true});
    }
    await page.goto(url);
    assert.equal(await page.locator('#delete-account-form').count(), 1);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.emulateMedia({colorScheme: 'dark'});
    const contrast = await page.locator('.page-intro').evaluate((element) => {
      const rgb = (value) => value.match(/[\d.]+/gu).slice(0, 3).map(Number);
      const luminance = (value) => rgb(value).map(channel => {
        const normalized = channel / 255;
        return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
      const foreground = luminance(getComputedStyle(element).color);
      const background = luminance(getComputedStyle(document.body).backgroundColor);
      return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
    });
    assert.ok(contrast >= 4.5, `dark intro contrast ${contrast.toFixed(2)}:1`);
    const linkContrast = await page.locator('.delete-steps a').evaluate((element) => {
      const luminance = (value) => value.match(/[\d.]+/gu).slice(0, 3).map(Number).map(channel => {
        const normalized = channel / 255;
        return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
      const foreground = luminance(getComputedStyle(element).color);
      const background = luminance(getComputedStyle(element.closest('section')).backgroundColor);
      return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
    });
    assert.ok(linkContrast >= 4.5, `dark export link contrast ${linkContrast.toFixed(2)}:1`);
    if (process.env.ID_BROWSER_SCREENSHOT_DIR) {
      await page.screenshot({path: path.join(process.env.ID_BROWSER_SCREENSHOT_DIR, 'delete-mobile-dark.png'), fullPage: true});
    }
    await page.setViewportSize({width: 1440, height: 900});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.setViewportSize({width: 320, height: 700});
    let calls = 0;
    await page.route('**/api/v1/auth/account/deletions', async (route) => {
      calls++;
      const request = route.request();
      const body = request.postDataJSON();
      assert.equal(body.password, 'password-example');
      assert.equal(body.mfa_code, '123456');
      assert.match(request.headers()['idempotency-key'], /^[0-9a-f-]{36}$/u);
      assert.equal(request.headers()['x-csrftoken'], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      await route.fulfill({status: 202, contentType: 'application/json', body: JSON.stringify({id: '123', status: 'pending'})});
    });
    await page.locator('#delete-password').fill('password-example');
    await page.locator('#delete-mfa').fill('123456');
    await page.locator('.delete-button').click();
    assert.equal(calls, 0, 'acknowledgement must be checked');
    await page.locator('#delete-understood').check();
    await page.locator('.delete-button').click();
    await page.locator('#delete-result:visible').waitFor();
    assert.equal(calls, 1);
    assert.match(await page.locator('#delete-result').innerText(), /Очистка данных выполняется отдельно/u);
    assert.equal(await page.locator('#delete-account-form').count(), 0);

    const uncertain = await context.newPage();
    await uncertain.route('**/api/v1/auth/account/deletions', route => route.abort());
    await uncertain.goto(url);
    await uncertain.locator('#delete-password').fill('password-example');
    await uncertain.locator('#delete-mfa').fill('123456');
    await uncertain.locator('#delete-understood').check();
    await uncertain.locator('.delete-button').click();
    await uncertain.locator('#delete-error:visible').waitFor();
    assert.match(await uncertain.locator('#delete-error').innerText(), /Запрос мог быть принят/u);
    assert.equal(await uncertain.locator('.delete-button').isDisabled(), true);

    const malformed = await context.newPage();
    await malformed.route('**/api/v1/auth/account/deletions', route => route.fulfill({
      status: 202, contentType: 'application/json', body: JSON.stringify({id: 123, status: 'pending'}),
    }));
    await malformed.goto(url);
    await malformed.locator('#delete-password').fill('password-example');
    await malformed.locator('#delete-mfa').fill('123456');
    await malformed.locator('#delete-understood').check();
    await malformed.locator('.delete-button').click();
    await malformed.locator('#delete-error:visible').waitFor();
    assert.match(await malformed.locator('#delete-error').innerText(), /Запрос мог быть принят/u);
    assert.equal(await malformed.locator('.delete-button').isDisabled(), true);

    const rejected = await context.newPage();
    await rejected.route('**/api/v1/auth/account/deletions', route => route.fulfill({
      status: 400, contentType: 'application/json', body: JSON.stringify({code: 'INVALID_PASSWORD'}),
    }));
    await rejected.goto(url);
    await rejected.locator('#delete-password').fill('wrong-password');
    await rejected.locator('#delete-mfa').fill('123456');
    await rejected.locator('#delete-understood').check();
    await rejected.locator('.delete-button').click();
    await rejected.locator('#delete-error:visible').waitFor();
    assert.match(await rejected.locator('#delete-error').innerText(), /Неверный текущий пароль/u);
    assert.equal(await rejected.locator('.delete-button').isEnabled(), true);
    await context.close();
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
