(() => {
  "use strict";

  const begin = document.getElementById("totp-begin");
  const pending = document.getElementById("totp-pending");
  const form = document.getElementById("totp-confirm-form");
  const recovery = document.getElementById("totp-recovery");
  const message = document.getElementById("totp-message");
  const error = document.getElementById("totp-error");
  if (!begin || !pending || !form || !recovery || !message || !error) return;

  const confirm = form.querySelector('button[type="submit"]');
  let busy = false;
  let recoveryVisible = false;
  const csrfCookie = () => {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  };

  async function post(path, payload) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(path, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      const data = await response.json();
      if (!response.ok || data.ok !== true) {
        throw new Error(typeof data.message === "string" ? data.message : "Операция недоступна.");
      }
      return data;
    } finally {
      clearTimeout(timeout);
    }
  }

  function fail(failure) {
    error.textContent = failure instanceof Error && failure.name !== "AbortError"
      ? failure.message
      : "Не удалось подтвердить результат. Обновите страницу и проверьте состояние MFA.";
    error.hidden = false;
  }

  begin.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    begin.disabled = true;
    begin.setAttribute("aria-busy", "true");
    begin.textContent = "Готовим настройку…";
    error.hidden = true;
    message.hidden = true;
    try {
      const data = await post("/api/v1/auth/mfa/totp/begin", {});
      if (typeof data.secret !== "string" || !/^data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+$/.test(data.svg_data_uri)) {
        throw new Error("Сервер вернул неверные данные настройки.");
      }
      document.getElementById("totp-secret").textContent = data.secret;
      document.getElementById("totp-qr").src = data.svg_data_uri;
      pending.hidden = false;
      form.querySelector("input").focus();
    } catch (failure) {
      fail(failure);
    } finally {
      busy = false;
      begin.disabled = false;
      begin.removeAttribute("aria-busy");
      begin.textContent = "Настроить приложение с кодами";
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    confirm.disabled = true;
    form.setAttribute("aria-busy", "true");
    confirm.textContent = "Проверяем код…";
    error.hidden = true;
    message.hidden = true;
    try {
      const code = form.querySelector("input").value.trim();
      const data = await post("/api/v1/auth/mfa/totp/confirm", { code });
      const totpStatus = document.getElementById("totp-status");
      if (totpStatus) totpStatus.textContent = "Включена";
      pending.hidden = true;
      begin.hidden = true;
      document.getElementById("totp-secret").textContent = "";
      document.getElementById("totp-qr").removeAttribute("src");
      if (Array.isArray(data.recovery_codes) && data.recovery_codes.length > 0) {
        const list = document.getElementById("totp-recovery-codes");
        list.replaceChildren();
        for (const code of data.recovery_codes) {
          const item = document.createElement("li");
          item.textContent = String(code);
          list.append(item);
        }
        recovery.hidden = false;
        recoveryVisible = true;
        const guidance = document.getElementById("recovery-guidance");
        if (guidance) guidance.hidden = true;
        const recoveryStatus = document.getElementById("recovery-status");
        const recoveryLeft = document.getElementById("recovery-left");
        if (recoveryStatus) recoveryStatus.textContent = "Есть";
        if (recoveryLeft) recoveryLeft.textContent = String(data.recovery_codes.length);
        const saved = document.getElementById("totp-recovery-saved");
        if (saved) saved.hidden = false;
      }
      message.textContent = "Приложение с одноразовыми кодами включено.";
      message.hidden = false;
    } catch (failure) {
      fail(failure);
    } finally {
      busy = false;
      confirm.disabled = false;
      form.removeAttribute("aria-busy");
      confirm.textContent = "Подтвердить и включить";
    }
  });

  document.getElementById("totp-recovery-saved")?.addEventListener("click", () => {
    recoveryVisible = false;
    window.location.reload();
  });

  window.addEventListener("beforeunload", (event) => {
    if (!recoveryVisible) return;
    event.preventDefault();
    event.returnValue = "";
  });
})();
