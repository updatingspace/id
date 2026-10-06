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

  const cancelBox = document.querySelector(".export-cancel[data-export-id]");
  const cancelStart = document.getElementById("export-cancel-start");
  const cancelReview = document.getElementById("export-cancel-review");
  const cancelConfirm = document.getElementById("export-cancel-confirm");
  const cancelKeep = document.getElementById("export-cancel-keep");
  const cancelError = document.getElementById("export-cancel-error");
  if (!cancelBox || !cancelStart || !cancelReview || !cancelConfirm || !cancelKeep || !cancelError) return;
  const id = cancelBox.dataset.exportId;
  if (!/^[0-9a-f]{32}$/u.test(id || "")) return;

  cancelStart.addEventListener("click", () => {
    cancelStart.hidden = true;
    cancelReview.hidden = false;
    cancelConfirm.focus();
  });
  cancelKeep.addEventListener("click", () => {
    cancelReview.hidden = true;
    cancelStart.hidden = false;
    cancelStart.focus();
  });
  cancelConfirm.addEventListener("click", async () => {
    cancelConfirm.disabled = true;
    cancelKeep.disabled = true;
    cancelError.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(`/api/v1/auth/data/exports/${id}`, {
        method: "DELETE", credentials: "include", cache: "no-store",
        headers: { "X-CSRFToken": csrfCookie(), Accept: "application/json" },
        signal: controller.signal,
      });
      if (response.status === 401) {
        window.location.assign("/login?next=%2Faccount");
        return;
      }
      if (response.status !== 202) {
        throw new Error(response.status === 404
          ? "Запрос больше не доступен в этом аккаунте. Проверьте письмо или обратитесь в поддержку."
          : "Не удалось подтвердить отзыв. Обновите состояние или обратитесь в поддержку.");
      }
      const section = cancelBox.closest("section");
      if (section) {
        const heading = document.createElement("h2");
        heading.textContent = "Запрос отозван";
        heading.tabIndex = -1;
        const message = document.createElement("p");
        message.setAttribute("role", "status");
        message.textContent = "Ссылка из письма больше не работает; удаление подготовленного файла может занять время.";
        const back = document.createElement("a");
        back.href = "/account?section=data";
        back.textContent = "К запросу копии данных";
        section.replaceChildren(heading, message, back);
        heading.focus();
      }
    } catch (failure) {
      cancelError.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message : "Ответ не получен. Проверьте состояние запроса перед повтором.";
      cancelError.hidden = false;
      cancelConfirm.disabled = false;
      cancelKeep.disabled = false;
    } finally { clearTimeout(timer); }
  });
})();
