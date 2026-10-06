(() => {
  "use strict";
  const button = document.getElementById("totp-disable");
  const error = document.getElementById("totp-disable-error");
  if (!button || !error) return;
  let busy = false;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  button.addEventListener("click", async () => {
    if (busy || !window.confirm("Отключить приложение с кодами? Если других способов MFA нет, резервные коды также будут удалены.")) return;
    busy = true;
    button.disabled = true;
    error.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/mfa/totp/disable", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "X-CSRFToken": csrfCookie() },
        signal: controller.signal,
      });
      if (response.status === 404) {
        window.location.reload();
        return;
      }
      const body = await response.json();
      if (!response.ok || body.ok !== true) {
        throw new Error(typeof body.message === "string" ? body.message : "Не удалось отключить TOTP.");
      }
      window.location.reload();
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить результат. Обновите страницу и проверьте состояние MFA.";
      error.hidden = false;
      busy = false;
      button.disabled = false;
    } finally {
      clearTimeout(timer);
    }
  });
})();
