(() => {
  "use strict";

  const form = document.getElementById("profile-form");
  const message = document.getElementById("profile-message");
  const error = document.getElementById("profile-error");
  if (!form || !message || !error) return;

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
    if (busy) return;
    busy = true;
    button.disabled = true;
    error.hidden = true;
    message.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const data = new FormData(form);
      const response = await fetch("/api/v1/auth/profile", {
        method: "PATCH",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify(Object.fromEntries(data.entries())),
        signal: controller.signal,
      });
      if (response.status === 401) {
        window.location.replace("/login?next=%2Faccount");
        return;
      }
      const result = await response.json();
      if (!response.ok || result.ok !== true) {
        throw new Error(typeof result.message === "string" ? result.message : "Не удалось сохранить профиль.");
      }
      message.textContent = "Профиль сохранён.";
      message.hidden = false;
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить сохранение. Обновите страницу и проверьте данные.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      busy = false;
      button.disabled = false;
    }
  });
})();
