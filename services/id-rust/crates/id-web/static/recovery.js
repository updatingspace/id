(() => {
  "use strict";

  const forgotForm = document.getElementById("forgot-form");
  const resetForm = document.getElementById("reset-form");
  const verifyForm = document.getElementById("verify-form");
  const verifyRequestForm = document.getElementById("verify-request-form");
  const submit = document.getElementById("submit");
  const status = document.getElementById("status");
  const error = document.getElementById("error");
  if ((!forgotForm && !resetForm && !verifyForm) || !submit || !status || !error) return;

  function show(message, failed = false) {
    const target = failed ? error : status;
    const other = failed ? status : error;
    target.textContent = message;
    target.hidden = false;
    other.hidden = true;
  }

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  async function jsonResponse(response) {
    try { return await response.json(); }
    catch { throw new Error("Сервис вернул неожиданный ответ. Попробуйте ещё раз."); }
  }

  function message(cause) {
    if (cause && cause.name === "AbortError") return "Превышено время ожидания. Попробуйте ещё раз.";
    return cause instanceof Error ? cause.message : "Не удалось выполнить запрос. Попробуйте ещё раз.";
  }

  async function withTimeout(action, button = submit) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    button.disabled = true;
    try { await action(controller.signal); }
    catch (cause) { show(message(cause), true); }
    finally { clearTimeout(timer); button.disabled = false; }
  }

  function headers() {
    const csrf = csrfCookie();
    const result = { "Content-Type": "application/json", Accept: "application/json" };
    // Legacy Ninja routes use the single-use form token and do not expose a
    // readable CSRF cookie. Rust routes set one; send it when available.
    if (csrf) result["X-CSRFToken"] = csrf;
    return result;
  }

  async function ensureCsrf(signal, purpose = "password_reset") {
    if (csrfCookie()) return;
    // A fresh browser opening an email link has not necessarily visited login.
    const issued = await fetch("/api/v1/auth/form_token?purpose=" + encodeURIComponent(purpose), {
      credentials: "include", cache: "no-store", headers: { Accept: "application/json" }, signal,
    });
    if (!issued.ok) {
      throw new Error("Не удалось подготовить защиту запроса. Обновите страницу.");
    }
  }

  if (forgotForm) forgotForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    void withTimeout(async (signal) => {
      show("Отправляем запрос…");
      const email = forgotForm.elements.namedItem("email").value.trim();
      const issued = await fetch("/api/v1/auth/form_token?purpose=password_reset", {
        credentials: "include", cache: "no-store", headers: { Accept: "application/json" }, signal,
      });
      const token = await jsonResponse(issued);
      if (!issued.ok || typeof token.form_token !== "string") {
        throw new Error(token.message || "Не удалось подготовить запрос. Попробуйте ещё раз.");
      }
      const response = await fetch("/api/v1/auth/password/reset/request", {
        method: "POST", credentials: "include", cache: "no-store", headers: headers(),
        body: JSON.stringify({ email, form_token: token.form_token }), signal,
      });
      const result = await jsonResponse(response);
      if (!response.ok) throw new Error(result.message || "Не удалось отправить запрос. Попробуйте позже.");
      // The service gives the same answer for known and unknown accounts.
      show("Если аккаунт с таким адресом существует, мы отправим письмо для восстановления.");
      forgotForm.reset();
    });
  });

  if (resetForm) {
    const parameters = new URLSearchParams(window.location.hash.slice(1));
    let key = parameters.get("key");
    // Keep the bearer credential out of navigation history and referrers.
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    if (!key || key.length > 512) {
      key = null;
      show("Ссылка недействительна. Запросите новое письмо.", true);
    } else {
      resetForm.hidden = false;
    }

    resetForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (submit.disabled || !key) return;
      const password = resetForm.elements.namedItem("password").value;
      const confirmation = resetForm.elements.namedItem("confirmation").value;
      if (password !== confirmation) { show("Пароли не совпадают.", true); return; }
      if (password.length < 10 || password.length > 4096) {
        show("Пароль должен содержать от 10 до 4096 символов.", true);
        return;
      }
      void withTimeout(async (signal) => {
        show("Сохраняем новый пароль…");
        await ensureCsrf(signal);
        const response = await fetch("/api/v1/auth/password/reset/confirm", {
          method: "POST", credentials: "include", cache: "no-store", headers: headers(),
          body: JSON.stringify({ key, password }), signal,
        });
        const result = await jsonResponse(response);
        if (!response.ok) throw new Error(result.message || "Ссылка недействительна или истекла. Запросите новую.");
        key = null;
        resetForm.reset();
        resetForm.hidden = true;
        show("Пароль изменён. Войдите с новым паролем.");
      });
    });
  }

  if (verifyForm) {
    const parameters = new URLSearchParams(window.location.hash.slice(1));
    let key = parameters.get("key");
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    if (key && key.length <= 512) verifyForm.hidden = false;
    else {
      key = null;
      show("Если ссылка недействительна или истекла, запросите новое письмо.", true);
    }
    verifyForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (submit.disabled || !key) return;
      void withTimeout(async (signal) => {
        show("Подтверждаем адрес…");
        await ensureCsrf(signal, "email_verification");
        const response = await fetch("/api/v1/auth/email/verification/confirm", {
          method: "POST", credentials: "include", cache: "no-store", headers: headers(),
          body: JSON.stringify({ key }), signal,
        });
        const result = await jsonResponse(response);
        if (!response.ok) throw new Error(result.message || "Ссылка недействительна или истекла.");
        key = null;
        verifyForm.hidden = true;
        verifyRequestForm.hidden = true;
        show("Email подтверждён. Теперь можно войти в аккаунт.");
      });
    });
    const resend = document.getElementById("resend-submit");
    verifyRequestForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (resend.disabled) return;
      void withTimeout(async (signal) => {
        show("Отправляем письмо…");
        const email = verifyRequestForm.elements.namedItem("email").value.trim();
        const issued = await fetch("/api/v1/auth/form_token?purpose=email_verification", {
          credentials: "include", cache: "no-store", headers: { Accept: "application/json" }, signal,
        });
        const token = await jsonResponse(issued);
        if (!issued.ok || typeof token.form_token !== "string") {
          throw new Error(token.message || "Не удалось подготовить запрос. Попробуйте ещё раз.");
        }
        const response = await fetch("/api/v1/auth/email/verification/request", {
          method: "POST", credentials: "include", cache: "no-store", headers: headers(),
          body: JSON.stringify({ email, form_token: token.form_token }), signal,
        });
        const result = await jsonResponse(response);
        if (!response.ok) throw new Error(result.message || "Не удалось отправить письмо. Попробуйте позже.");
        show("Если адрес ожидает подтверждения, мы отправим письмо со ссылкой.");
        verifyRequestForm.reset();
      }, resend);
    });
  }
})();
