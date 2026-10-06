(() => {
  "use strict";

  const error = document.getElementById("session-error");
  const message = document.getElementById("session-message");
  const buttons = Array.from(document.querySelectorAll("[data-revoke-session], #revoke-others"));
  if (!error || !message) return;
  let busy = false;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  async function revoke(url, body) {
    if (busy) return;
    busy = true;
    buttons.forEach((button) => { button.disabled = true; });
    error.hidden = true;
    message.hidden = false;
    message.textContent = "Завершаем сессию…";
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(url, {
        method: body ? "POST" : "DELETE",
        credentials: "include",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "X-CSRFToken": csrfCookie(),
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        signal: controller.signal,
      });
      if (response.status === 401) {
        window.location.replace("/login?next=%2Faccount%3Fsection%3Dsessions");
        return;
      }
      if (!response.ok) throw new Error("Не удалось завершить сессию. Обновите страницу и проверьте её состояние.");
      window.location.reload();
    } catch {
      message.hidden = true;
      error.textContent = "Не удалось подтвердить отзыв доступа. Обновите страницу и проверьте состояние сессий.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      busy = false;
      buttons.forEach((button) => { button.disabled = false; });
    }
  }

  buttons.forEach((button) => button.addEventListener("click", () => {
    const sessionId = button.getAttribute("data-revoke-session");
    if (sessionId) void revoke("/api/v1/auth/sessions/" + encodeURIComponent(sessionId));
    else if (button.id === "revoke-others") void revoke("/api/v1/auth/sessions/bulk", { all_except_current: true });
  }));
})();
