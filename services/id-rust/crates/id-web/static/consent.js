(() => {
  "use strict";
  const form = document.getElementById("consent-form");
  const deny = document.getElementById("deny");
  const approve = document.getElementById("approve");
  const error = document.getElementById("consent-error");
  if (!form || !deny || !approve || !error) return;

  function csrfCookie() {
    const name = form.dataset.csrfCookie || "csrftoken";
    const entry = document.cookie.split("; ").find((item) => item.startsWith(name + "="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice(name.length + 1)); }
    catch { return ""; }
  }

  async function decide(approved) {
    if (approve.disabled || deny.disabled) return;
    const csrf = csrfCookie();
    if (!csrf) { error.textContent = "Сессия формы истекла. Обновите страницу."; error.hidden = false; return; }
    approve.disabled = true;
    deny.disabled = true;
    error.hidden = true;
    const scopes = Array.from(form.querySelectorAll('input[name="scope"]:checked'))
      .map((input) => input.value);
    const payload = approved
      ? { request_id: form.dataset.requestId, scopes, remember: document.getElementById("remember").checked }
      : { request_id: form.dataset.requestId };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(approved ? "/oauth/authorize/approve" : "/oauth/authorize/deny", {
        method: "POST", credentials: "include", cache: "no-store", signal: controller.signal,
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrf, Accept: "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json();
      if (!response.ok || typeof body.redirect_uri !== "string") throw new Error("Не удалось сохранить решение. Обновите страницу и попробуйте снова.");
      window.location.assign(body.redirect_uri);
    } catch {
      error.textContent = "Не удалось сохранить решение. Обновите страницу и попробуйте снова.";
      error.hidden = false;
      approve.disabled = false;
      deny.disabled = false;
    } finally { clearTimeout(timeout); }
  }

  form.addEventListener("submit", (event) => { event.preventDefault(); void decide(true); });
  deny.addEventListener("click", () => { void decide(false); });
})();
