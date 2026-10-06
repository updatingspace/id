(() => {
  "use strict";

  const button = document.getElementById("logout");
  const error = document.getElementById("logout-error");
  if (!button || !error) return;
  let busy = false;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  button.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    button.disabled = true;
    error.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      // A lost response after commit is possible. The follow-up /me, not the
      // POST status alone, proves this browser can no longer use the session.
      try {
        await fetch("/api/v1/auth/logout", {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          headers: { Accept: "application/json", "X-CSRFToken": csrfCookie() },
          signal: controller.signal,
        });
      } catch {}
      const restored = await fetch("/api/v1/auth/me", {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!restored.ok || (await restored.json()).user !== null) {
        throw new Error("session still active or unavailable");
      }
      try { window.sessionStorage.removeItem("id_session_token"); } catch {}
      window.location.replace("/login");
    } catch {
      error.textContent = "Не удалось подтвердить выход. Проверьте состояние сессии и повторите действие.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      busy = false;
      button.disabled = false;
    }
  });
})();
