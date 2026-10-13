(() => {
  "use strict";
  const form = document.getElementById("preferences-form");
  const message = document.getElementById("preferences-message");
  const error = document.getElementById("preferences-error");
  const button = form?.querySelector('button[type="submit"]');
  let busy = false;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  if (form && button && message && error) form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    const data = new FormData(form);
    form.setAttribute('aria-busy', 'true');
    for (const select of form.querySelectorAll('select')) select.disabled = true;
    button.disabled = true;
    message.hidden = true;
    error.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const payload = { language: data.get("language"), timezone: data.get("timezone") };
      const response = await fetch("/api/v1/auth/preferences", {
        method: "PATCH",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (response.status === 401) {
        window.location.replace("/login?next=%2Faccount%3Fsection%3Dprofile");
        return;
      }
      const result = await response.json();
      if (!response.ok || typeof result.language !== "string") {
        throw new Error(typeof result.message === "string" ? result.message : "Не удалось сохранить настройки.");
      }
      message.textContent = "Настройки сохранены.";
      message.hidden = false;
      const language = document.querySelector('[data-preference-language]');
      if (language) language.textContent = result.language === 'en' ? 'English' : 'Русский';
      const timezone = document.querySelector('[data-preference-timezone]');
      if (timezone) timezone.textContent = [...form.querySelector('[name=timezone]').options]
        .find(option => option.value === result.timezone)?.textContent || result.timezone || 'Не выбран';
      form.closest('dialog')?.close();
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить сохранение. Обновите страницу и проверьте настройки.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      busy = false;
      form.removeAttribute('aria-busy');
      for (const select of form.querySelectorAll('select')) select.disabled = false;
      button.disabled = false;
    }
  });

  const consentMessage = document.getElementById("consents-message");
  const consentError = document.getElementById("consents-error");
  for (const button of document.querySelectorAll("button.consent-revoke")) {
    button.addEventListener("click", async () => {
      if (button.disabled) return;
      button.disabled = true;
      if (consentMessage) consentMessage.hidden = true;
      if (consentError) consentError.hidden = true;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30000);
      try {
        const kind = button.dataset.kind;
        if (kind !== "marketing") throw new Error("Это согласие нельзя отозвать здесь.");
        const response = await fetch("/api/v1/auth/consents/revoke?kind=" + encodeURIComponent(kind), {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          headers: { "X-CSRFToken": csrfCookie() },
          signal: controller.signal,
        });
        if (response.status === 401) {
          window.location.replace("/login?next=%2Faccount%3Fsection%3Dprivacy");
          return;
        }
        const result = await response.json();
        if (!response.ok || result.ok !== true) {
          throw new Error(typeof result.message === "string" ? result.message : "Не удалось отозвать согласие.");
        }
        if (consentMessage) {
          consentMessage.textContent = "Согласие отозвано.";
          consentMessage.hidden = false;
        }
        window.location.reload();
      } catch (failure) {
        if (consentError) {
          consentError.textContent = failure instanceof Error && failure.name !== "AbortError"
            ? failure.message
            : "Не удалось подтвердить отзыв. Обновите страницу и проверьте состояние согласия.";
          consentError.hidden = false;
        }
        button.disabled = false;
      } finally {
        clearTimeout(timer);
      }
    });
  }
})();
