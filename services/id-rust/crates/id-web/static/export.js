(() => {
  "use strict";

  const form = document.getElementById("export-form");
  const error = document.getElementById("export-error");
  if (!form || !error) return;
  const button = form.querySelector('button[type="submit"]');
  if (!button) return;

  const pendingKey = "id-export-idempotency-key";
  const csrfCookie = () => {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  };
  let busy = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    button.disabled = true;
    error.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      let key = sessionStorage.getItem(pendingKey);
      if (!key) {
        key = crypto.randomUUID();
        sessionStorage.setItem(pendingKey, key);
      }
      const response = await fetch("/api/v1/auth/data/exports", {
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
      if (response.status === 401) {
        window.location.replace("/login?next=%2Faccount");
        return;
      }
      const result = await response.json();
      if (response.status !== 202 || !/^[0-9a-f]{32}$/u.test(result.id)) {
        const message = result.error === "INVALID_PASSWORD" ? "Неверный текущий пароль."
          : result.error === "MFA_REQUIRED" ? "Нужен код MFA."
          : result.error === "INVALID_MFA_CODE" ? "Неверный или уже использованный код MFA."
          : "Не удалось запустить экспорт. Повторите попытку позже.";
        throw new Error(message);
      }
      form.reset();
      sessionStorage.removeItem(pendingKey);
      window.location.assign(`/account?section=data&export=${result.id}`);
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message : "Ответ не получен. Повторите запрос: операция не будет создана дважды.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      busy = false;
      button.disabled = false;
    }
  });
})();
