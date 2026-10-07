(() => {
  "use strict";

  const form = document.getElementById("delete-account-form");
  const error = document.getElementById("delete-error");
  const result = document.getElementById("delete-result");
  if (!form || !error || !result) return;
  const button = form.querySelector('button[type="submit"]');
  if (!button) return;

  const csrfCookie = () => {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  };
  let submitted = false;
  let key;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submitted || !form.reportValidity()) return;
    submitted = true;
    button.disabled = true;
    error.hidden = true;
    key ||= crypto.randomUUID();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/account/deletions", {
        method: "POST", credentials: "include", cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfCookie(),
          "Idempotency-Key": key,
        },
        body: JSON.stringify({
          password: form.elements.namedItem("password")?.value || "",
          mfa_code: form.elements.namedItem("mfa_code")?.value || undefined,
        }),
        signal: controller.signal,
      });
      const data = await response.json();
      if (response.status === 202 && typeof data.id === "string" && /^[1-9][0-9]{0,18}$/u.test(data.id)) {
        form.remove();
        result.textContent = `Запрос № ${data.id} принят. Доступ к аккаунту закрыт. Очистка данных выполняется отдельно и ещё не завершена. Сохраните номер запроса для обращения в поддержку.`;
        result.hidden = false;
        result.focus();
        return;
      }
      const messages = {
        INVALID_PASSWORD: "Неверный текущий пароль.",
        MFA_REQUIRED: "Введите код приложения или резервный код.",
        INVALID_MFA_CODE: "Неверный или уже использованный код дополнительной защиты.",
        PASSWORD_CHANGED: "Пароль был изменён. Войдите в аккаунт заново.",
        CSRF_FAILED: "Сессия формы устарела. Обновите страницу и повторите действие.",
      };
      if (messages[data.code] && response.status !== 202) {
        error.textContent = messages[data.code];
        submitted = false;
        button.disabled = false;
      } else {
        error.textContent = response.status === 401
          ? "Сессия закончилась. Проверьте состояние аккаунта перед повтором."
          : "Не удалось подтвердить результат. Запрос мог быть принят. Не повторяйте удаление вслепую; обратитесь в поддержку.";
      }
      error.hidden = false;
    } catch {
      error.textContent = "Ответ не получен. Запрос мог быть принят. Не повторяйте удаление вслепую: проверьте вход в аккаунт или обратитесь в поддержку.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
    }
  });
})();
