(() => {
  "use strict";
  const button = document.getElementById("recovery-rotate");
  const result = document.getElementById("recovery-rotation-result");
  const list = document.getElementById("recovery-rotation-codes");
  const error = document.getElementById("recovery-rotation-error");
  if (!button || !result || !list || !error) return;

  let busy = false;
  let rotationKey = null;
  let codesVisible = false;
  const csrfCookie = () => {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  };

  button.addEventListener("click", async () => {
    if (busy) return;
    if (!rotationKey) {
      if (!window.confirm("Обновить резервные коды? Все прежние неиспользованные коды перестанут работать.")) return;
      rotationKey = crypto.randomUUID();
    }
    busy = true;
    button.disabled = true;
    error.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/mfa/recovery/regenerate", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "X-CSRFToken": csrfCookie(), "Idempotency-Key": rotationKey },
        signal: controller.signal,
      });
      const body = await response.json();
      if (!response.ok || body.ok !== true || !Array.isArray(body.recovery_codes)) {
        throw new Error(typeof body.message === "string" ? body.message : "Не удалось обновить коды.");
      }
      if (body.recovery_codes.length !== 10 || body.recovery_codes.some(code => !/^\d{8}$/.test(code))) {
        throw new Error("Сервер вернул неверный набор кодов. Проверьте состояние MFA.");
      }
      for (const code of body.recovery_codes) {
        const item = document.createElement("li");
        item.textContent = code;
        list.append(item);
      }
      result.hidden = false;
      button.hidden = true;
      codesVisible = true;
      document.getElementById("recovery-status").textContent = "Есть";
      document.getElementById("recovery-left").textContent = String(body.recovery_codes.length);
      rotationKey = null;
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить результат. Нажмите кнопку ещё раз, не перезагружая страницу.";
      error.hidden = false;
      button.disabled = false;
    } finally {
      clearTimeout(timer);
      busy = false;
    }
  });

  document.getElementById("recovery-rotation-saved")?.addEventListener("click", () => {
    codesVisible = false;
    window.location.reload();
  });

  window.addEventListener("beforeunload", (event) => {
    if (!codesVisible) return;
    event.preventDefault();
    event.returnValue = "";
  });
})();
