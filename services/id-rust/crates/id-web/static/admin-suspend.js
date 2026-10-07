(() => {
  "use strict";
  const form = document.getElementById("suspend-form");
  const result = document.getElementById("suspend-result");
  if (!form || !result) return;
  const button = form.querySelector('button[type="submit"]');
  const csrfCookie = () => {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  };
  const show = (message, alert = false) => {
    result.textContent = message;
    result.hidden = false;
    result.setAttribute("role", alert ? "alert" : "status");
    result.focus();
  };
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    const id = form.dataset.accountId;
    const subject = form.dataset.subject;
    if (!id || !subject || !/^\d{1,10}$/.test(id)) {
      show("Не удалось проверить аккаунт. Вернитесь к поиску и попробуйте снова.", true);
      return;
    }
    button.disabled = true;
    result.hidden = true;
    try {
      const response = await fetch(`/api/v1/auth/admin/accounts/${id}/suspend`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie(), Accept: "application/json" },
        body: JSON.stringify({
          expected_subject: subject,
          current_password: form.elements.current_password.value,
          reason: form.elements.reason.value,
        }),
      });
      form.elements.current_password.value = "";
      if (response.status === 200) {
        const check = await fetch(`/api/v1/auth/admin/accounts/${id}`, {
          credentials: "include", headers: { Accept: "application/json" },
        });
        const state = check.ok ? (await check.json()).account?.access_state : null;
        if (state === "account_disabled") {
          form.hidden = true;
          show("Вход заблокирован. Сессии и токены отозваны. Проверьте запись в журнале и уведомите владельца по регламенту.");
        } else {
          show("Запрос принят, но итоговое состояние не подтверждено. Откройте карточку аккаунта и проверьте его повторно.", true);
        }
      } else if (response.status === 400) {
        show("Не удалось подтвердить пароль оператора. Проверьте его и повторите попытку.", true);
      } else if (response.status === 401 || response.status === 403) {
        show("Сессия или права оператора изменились. Войдите снова и проверьте аккаунт.", true);
      } else if (response.status === 409) {
        show("Данные аккаунта изменились. Вернитесь к карточке и начните проверку заново.", true);
      } else {
        show("Результат неизвестен. Не повторяйте действие вслепую: сначала проверьте состояние аккаунта.", true);
      }
    } catch {
      form.elements.current_password.value = "";
      show("Связь прервалась. Результат неизвестен; сначала проверьте состояние аккаунта.", true);
    } finally {
      button.disabled = false;
    }
  });
})();
