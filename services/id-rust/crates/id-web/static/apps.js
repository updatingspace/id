(() => {
  "use strict";
  const buttons = Array.from(document.querySelectorAll("[data-revoke-app]"));
  const message = document.getElementById("apps-message");
  const error = document.getElementById("apps-error");
  const review = document.getElementById("revoke-app-review");
  const description = document.getElementById("revoke-app-description");
  const confirm = document.getElementById("revoke-app-confirm");
  const cancel = document.getElementById("revoke-app-cancel");
  if (!message || !error || !review || !description || !confirm || !cancel) return;
  let busy = false;
  let selected = null;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  async function revoke(clientId) {
    if (busy) return;
    busy = true;
    buttons.forEach((button) => { button.disabled = true; });
    message.textContent = "Отзываем доступ…";
    message.hidden = false;
    error.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/oauth/apps/revoke", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify({ client_id: clientId }),
        signal: controller.signal,
      });
      if (response.status === 401) {
        window.location.replace("/login?next=%2Faccount%3Fsection%3Dapps");
        return;
      }
      if (!response.ok) throw new Error("Не удалось отозвать доступ. Обновите страницу и проверьте состояние приложения.");
      window.location.reload();
    } catch {
      message.hidden = true;
      error.textContent = "Не удалось подтвердить отзыв доступа. Обновите страницу и проверьте состояние приложения.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      busy = false;
      buttons.forEach((button) => { button.disabled = false; });
    }
  }

  buttons.forEach((button) => button.addEventListener("click", () => {
    if (busy) return;
    const clientId = button.getAttribute("data-revoke-app");
    if (!clientId) return;
    selected = button;
    const appName = button.closest("li")?.querySelector("strong")?.textContent?.trim() || "этого приложения";
    description.textContent = `Вы собираетесь отозвать доступ для ${appName}. При следующем обращении приложение может попросить войти снова. Вы сможете разрешить доступ повторно.`;
    review.hidden = false;
    review.scrollIntoView({ block: "nearest" });
    confirm.focus();
  }));
  confirm.addEventListener("click", () => {
    const clientId = selected?.getAttribute("data-revoke-app");
    if (clientId) void revoke(clientId);
  });
  cancel.addEventListener("click", () => {
    review.hidden = true;
    selected?.focus();
    selected = null;
  });
})();
