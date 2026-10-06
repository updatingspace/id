(() => {
  "use strict";

  const verify = document.getElementById("email-verify-request");
  const cancel = document.getElementById("email-change-cancel");
  const change = document.getElementById("email-change-form");
  const message = document.getElementById("email-message");
  const error = document.getElementById("email-error");
  if ((!verify && !cancel && !change) || !message || !error) return;
  let busy = false;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  async function jsonRequest(path, method, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(path, {
        method,
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      const payload = await response.json();
      if (response.status === 401 && payload.code !== "REAUTH_REQUIRED") {
        window.location.replace("/login?next=%2Faccount");
        throw new Error("Требуется повторный вход.");
      }
      if (!response.ok) {
        throw new Error(typeof payload.message === "string"
          ? payload.message : "Не удалось выполнить действие.");
      }
      return payload;
    } finally {
      clearTimeout(timer);
    }
  }

  async function run(button, action, success) {
    if (busy) return;
    busy = true;
    button.disabled = true;
    message.hidden = true;
    error.hidden = true;
    try {
      await action();
      message.textContent = success;
      message.hidden = false;
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить результат. Обновите страницу и проверьте состояние почты.";
      error.hidden = false;
    } finally {
      busy = false;
      button.disabled = false;
    }
  }

  verify?.addEventListener("click", () => run(verify, async () => {
    const email = verify.dataset.email;
    if (!email) throw new Error("Адрес почты не найден.");
    const token = await jsonRequest("/api/v1/auth/form_token?purpose=email_verification", "GET");
    if (typeof token.form_token !== "string") throw new Error("Не удалось подготовить форму.");
    await jsonRequest("/api/v1/auth/email/verification/request", "POST", {
      email, form_token: token.form_token,
    });
  }, "Если адрес ожидает подтверждения, письмо со ссылкой придёт на него."));

  cancel?.addEventListener("click", () => run(cancel, async () => {
    await jsonRequest("/api/v1/auth/email/change", "DELETE");
    const pending = cancel.previousElementSibling;
    if (pending) pending.remove();
    cancel.remove();
  }, "Ожидающая смена адреса отменена."));

  change?.addEventListener("submit", (event) => {
    event.preventDefault();
    const input = change.querySelector('input[name="new_email"]');
    const button = change.querySelector('button[type="submit"]');
    if (!input || !button || !change.reportValidity()) return;
    return run(button, async () => {
      await jsonRequest("/api/v1/auth/email/change", "POST", { new_email: input.value.trim() });
      input.value = "";
    }, "Проверьте новый адрес: письмо с подтверждением отправлено. Обновите страницу, чтобы увидеть статус.");
  });
})();
