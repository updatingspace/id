// Real Chromium → Topcoat → Rust API → local YDB TOTP enrollment.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');

const origin = process.env.ID_LIVE_BASE_URL;
const fixturePath = process.env.ID_TOTP_BROWSER_FIXTURE_OUTPUT;
const playwrightModule = process.env.ID_PLAYWRIGHT_MODULE;
if (!origin || !fixturePath || !playwrightModule) {
  console.error('Set ID_LIVE_BASE_URL, ID_TOTP_BROWSER_FIXTURE_OUTPUT and ID_PLAYWRIGHT_MODULE');
  process.exit(2);
}
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
assert.equal(fixture.synthetic, true);
assert.equal(fixture.format_version, 1);
const { chromium } = require(playwrightModule);

function decodeBase32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let count = 0;
  const bytes = [];
  for (const char of text) {
    const value = alphabet.indexOf(char);
    assert(value >= 0, 'invalid TOTP secret alphabet');
    bits = (bits << 5) | value;
    count += 5;
    if (count >= 8) {
      count -= 8;
      bytes.push((bits >>> count) & 255);
      bits &= (1 << count) - 1;
    }
  }
  return Buffer.from(bytes);
}

function totp(secret, unixSeconds) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / 30)));
  const digest = crypto.createHmac('sha1', decodeBase32(secret)).update(counter).digest();
  const offset = digest[19] & 15;
  const value = (digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(value).padStart(6, '0');
}

async function main() {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.ID_CHROMIUM_PATH ? { executablePath: process.env.ID_CHROMIUM_PATH } : {}),
  });
  try {
    const context = await browser.newContext();
    await context.addCookies([{
      name: 'sessionid', value: fixture.session_token, url: origin, httpOnly: true,
    }]);
    const page = await context.newPage();
    const unexpectedDialogs = [];
    page.on('dialog', async dialog => {
      if (dialog.type() !== 'confirm') unexpectedDialogs.push(dialog.type());
      await dialog.accept();
    });
    await page.goto(origin + '/account?section=security');
    assert.equal(await page.locator('h1').textContent(), 'Безопасность');
    assert.equal(await page.locator('#totp-begin').isVisible(), true);
    assert((await context.cookies(origin)).some(cookie => cookie.name === 'csrftoken'));

    const deniedWithoutCsrf = await page.evaluate(async () => {
      const response = await fetch('/api/v1/auth/mfa/totp/begin', {
        method: 'POST', credentials: 'include',
      });
      return response.status;
    });
    assert.equal(deniedWithoutCsrf, 403);

    await page.locator('#totp-begin').click();
    await page.locator('#totp-pending').waitFor({ state: 'visible' });
    const secret = await page.locator('#totp-secret').textContent();
    assert.match(secret, /^[A-Z2-7]{32}$/);
    assert.match(await page.locator('#totp-qr').getAttribute('src'), /^data:image\/svg\+xml;base64,/);

    const now = Math.floor(Date.now() / 1000);
    const candidates = new Set([totp(secret, now), totp(secret, now + 30)]);
    const wrong = ['000000', '000001', '000002'].find(value => !candidates.has(value));
    await page.locator('#totp-code').fill(wrong);
    await page.locator('#totp-confirm-form button').click();
    await page.locator('#totp-error').waitFor({ state: 'visible' });
    assert.match(await page.locator('#totp-error').textContent(), /Неверный код/);

    if (Math.floor(Date.now() / 1000) % 30 >= 27) {
      await new Promise(resolve => setTimeout(resolve, 4000));
    }
    const code = totp(secret, Math.floor(Date.now() / 1000));
    await page.locator('#totp-code').fill(code);
    await page.locator('#totp-confirm-form button').click();
    await page.locator('#totp-recovery').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#totp-recovery-codes li').count(), 10);
    const originalCodes = await page.locator('#totp-recovery-codes li').allTextContents();
    assert.equal(await page.locator('#totp-secret').textContent(), '');
    assert.equal(await page.locator('#totp-qr').getAttribute('src'), null);
    assert.equal(await page.locator('#totp-status').textContent(), 'Включена');
    assert.equal(await page.locator('#recovery-status').textContent(), 'Есть');
    assert.equal(await page.locator('#recovery-left').textContent(), '10');

    await page.locator('#totp-recovery-saved').click();
    await page.locator('#totp-disable').waitFor();
    assert.equal(await page.locator('h1').textContent(), 'Безопасность');
    assert.equal(await page.locator('#totp-status').textContent(), 'Включена');
    assert.equal(await page.locator('#totp-begin').count(), 0);
    assert.equal(await page.locator('#totp-recovery-codes').count(), 0);
    assert.equal(await page.locator('#recovery-rotate').isVisible(), true);
    await page.locator('#recovery-rotate').click();
    await page.locator('#recovery-rotation-result').waitFor({ state: 'visible' });
    const rotatedCodes = await page.locator('#recovery-rotation-codes li').allTextContents();
    assert.equal(rotatedCodes.length, 10);
    assert.notDeepEqual(rotatedCodes, originalCodes);
    await page.locator('#recovery-rotation-saved').click();
    await page.locator('#recovery-rotate').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#recovery-rotation-codes li').count(), 0);
    assert.equal(await page.locator('#totp-disable').isVisible(), true);
    await page.locator('#totp-disable').click();
    await page.locator('#totp-begin').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#totp-status').textContent(), 'Не включена');
    assert.equal(await page.locator('#recovery-status').textContent(), 'Нет');
    assert.equal(await page.locator('#recovery-left').textContent(), '0');
    assert.deepEqual(unexpectedDialogs, [], 'saved-codes actions must release the beforeunload warning');
    console.log('PASS: Chromium TOTP setup, recovery-code rotation, CSRF and invalid-code denial, persistence and disable');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
