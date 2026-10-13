(() => {
  "use strict";

  const form = document.getElementById("password-change-form");
  const error = document.getElementById("password-change-error");
  const message = document.getElementById("password-change-message");
  if (!(form instanceof HTMLFormElement) || !error || !message) return;
  const button = form.querySelector('button[type="submit"]');
  let busy = false;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    const current = form.elements.namedItem("current_password");
    const next = form.elements.namedItem("new_password");
    const confirmation = form.elements.namedItem("confirm_password");
    if (!(current instanceof HTMLInputElement) || !(next instanceof HTMLInputElement)) return;
    if (!(confirmation instanceof HTMLInputElement)) {
      error.textContent = "Обновите страницу, чтобы подтвердить новый пароль.";
      error.hidden = false;
      return;
    }
    if (next.value !== confirmation.value) {
      error.textContent = "Пароли не совпадают. Повторите новый пароль.";
      error.hidden = false;
      confirmation.setAttribute("aria-invalid", "true");
      confirmation.focus();
      return;
    }
    confirmation.removeAttribute("aria-invalid");
    busy = true;
    if (button) button.disabled = true;
    error.hidden = true;
    message.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/change_password", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify({ current_password: current.value, new_password: next.value }),
        signal: controller.signal,
      });
      const body = await response.json();
      if (!response.ok || body.ok !== true) {
        const reasons = {
          WRONG_CURRENT_PASSWORD: "Текущий пароль введён неверно.",
          WEAK_PASSWORD: "Новый пароль не подходит. Проверьте правила под полем и выберите другой.",
          PASSWORD_CHANGED: "Пароль уже изменён в другом сеансе. Войдите заново.",
        };
        throw new Error(reasons[body.code] || (typeof body.message === "string" ? body.message : "Пароль не изменён."));
      }
      form.reset();
      try { window.sessionStorage.removeItem("id_session_token"); } catch {}
      message.textContent = "Пароль изменён. Войдите заново.";
      message.hidden = false;
      window.location.replace("/login");
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить результат. Обновите страницу и проверьте вход с новым паролем.";
      error.hidden = false;
      busy = false;
      if (button) button.disabled = false;
    } finally {
      clearTimeout(timer);
    }
  });
})();
