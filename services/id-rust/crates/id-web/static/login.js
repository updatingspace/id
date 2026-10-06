(() => {
  "use strict";

  const form = document.getElementById("login-form");
  const submit = document.getElementById("submit");
  const error = document.getElementById("error");
  const status = document.getElementById("status");
  const authContext = document.getElementById("auth-context");
  const mfaFields = document.getElementById("mfa-fields");
  const mfaMethod = document.getElementById("mfa-method");
  const mfaCode = document.getElementById("mfa-code");
  const passkeyButton = document.getElementById("passkey-login");
  if (!form || !submit || !error || !status || !mfaFields || !mfaMethod || !mfaCode) return;

  if (passkeyButton && window.isSecureContext && window.PublicKeyCredential && navigator.credentials?.get) {
    passkeyButton.hidden = false;
  }

  function safeReturnPath(value) {
    if (!value || /[\\\u0000-\u0020\u007f]/u.test(value)) return "/account";
    try {
      const target = new URL(value, window.location.origin);
      if (target.origin !== window.location.origin) return "/account";
      if (!["/", "/account", "/authorize", "/oauth/consent"].includes(target.pathname)) return "/account";
      if (target.searchParams.has("next")) return "/account";
      return target.pathname + target.search + target.hash;
    } catch {
      return "/account";
    }
  }

  const requestedNext = new URLSearchParams(window.location.search).get("next");
  const returnPath = safeReturnPath(requestedNext);
  if (authContext && requestedNext && (returnPath.startsWith("/oauth/consent?") || returnPath.startsWith("/authorize?"))) {
    document.getElementById("login-title").textContent = "Подтвердите вход";
    document.querySelector(".intro").textContent = "Вы переходите из другого сервиса через UpdSpace ID.";
    submit.textContent = "Продолжить к разрешениям";
    authContext.textContent = "После подтверждения аккаунта мы покажем название приложения и запрошенные сведения. Сам вход ещё не даёт приложению доступ: решение вы примете на следующем шаге.";
    authContext.hidden = false;
  }

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  function showError(message) {
    error.textContent = message;
    error.hidden = false;
    status.hidden = true;
  }

  async function jsonResponse(response) {
    try { return await response.json(); }
    catch { throw new Error("Сервис вернул неожиданный ответ. Попробуйте ещё раз."); }
  }

  function legacyToken() {
    try { return window.sessionStorage.getItem("id_session_token"); }
    catch { return null; }
  }

  function clearLegacyToken() {
    try { window.sessionStorage.removeItem("id_session_token"); } catch {}
  }

  function base64urlBytes(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
      throw new Error("Сервер вернул неверные параметры Passkey.");
    }
    const raw = atob(value.replace(/-/gu, "+").replace(/_/gu, "/"));
    return Uint8Array.from(raw, (character) => character.charCodeAt(0));
  }

  function base64url(value) {
    const bytes = new Uint8Array(value);
    let raw = "";
    for (const byte of bytes) raw += String.fromCharCode(byte);
    return btoa(raw).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
  }

  function passkeyOptions(input) {
    const options = input?.publicKey ?? input;
    if (!options || typeof options !== "object") throw new Error("Сервер не вернул параметры Passkey.");
    const mapped = { ...options, challenge: base64urlBytes(options.challenge) };
    if (Array.isArray(options.allowCredentials)) {
      mapped.allowCredentials = options.allowCredentials.map((item) => ({ ...item, id: base64urlBytes(item.id) }));
    }
    return mapped;
  }

  function assertionJson(credential) {
    const response = credential.response;
    if (!(response instanceof AuthenticatorAssertionResponse)) {
      throw new Error("Ключ не вернул ответ для входа. Повторите попытку.");
    }
    return {
      id: credential.id,
      rawId: base64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: base64url(response.clientDataJSON),
        authenticatorData: base64url(response.authenticatorData),
        signature: base64url(response.signature),
        userHandle: response.userHandle ? base64url(response.userHandle) : null,
      },
    };
  }

  async function restoreLegacySession() {
    const next = new URLSearchParams(window.location.search).get("next");
    const token = legacyToken();
    if (!next || !token) return;
    if (token.length > 512 || !/^[\x21-\x7e]+$/u.test(token)) {
      clearLegacyToken();
      return;
    }
    submit.disabled = true;
    if (passkeyButton) passkeyButton.disabled = true;
    status.hidden = false;
    status.textContent = "Проверяем существующую сессию…";
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), 10000);
    const readMe = (headers = {}) => fetch("/api/v1/auth/me", {
      credentials: "include",
      cache: "no-store",
      headers: { Accept: "application/json", ...headers },
      signal: timeout.signal,
    });
    try {
      const cookieResponse = await readMe();
      const cookieBody = await jsonResponse(cookieResponse);
      if (!cookieResponse.ok) throw new Error("Не удалось проверить существующую сессию.");
      if (cookieBody.user) {
        // A valid cookie is authoritative for this browser. Never replace its
        // identity with a stale explicit token from another tab.
        clearLegacyToken();
        status.hidden = true;
        return;
      }
      const explicitResponse = await readMe({ "X-Session-Token": token });
      if (explicitResponse.status === 401) {
        clearLegacyToken();
        showError("Старая сессия истекла. Войдите заново.");
        return;
      }
      const explicitBody = await jsonResponse(explicitResponse);
      if (!explicitResponse.ok || !explicitBody.user) {
        throw new Error("Не удалось восстановить существующую сессию.");
      }
      // /me must set a real HttpOnly cookie before the token can be discarded.
      const restoredResponse = await readMe();
      const restoredBody = await jsonResponse(restoredResponse);
      if (!restoredResponse.ok || !restoredBody.user ||
          JSON.stringify(restoredBody.user) !== JSON.stringify(explicitBody.user)) {
        throw new Error("Не удалось подтвердить восстановление сессии.");
      }
      clearLegacyToken();
      window.location.replace(safeReturnPath(next));
    } catch (cause) {
      showError(cause && cause.name === "AbortError"
        ? "Превышено время ожидания. Войдите заново или повторите попытку позже."
        : "Не удалось проверить существующую сессию. Вы можете войти заново.");
    } finally {
      clearTimeout(timer);
      submit.disabled = false;
      if (passkeyButton) passkeyButton.disabled = false;
    }
  }

  mfaMethod.addEventListener("change", () => {
    mfaCode.value = "";
    const recovery = mfaMethod.value === "recovery";
    mfaCode.autocomplete = recovery ? "off" : "one-time-code";
    mfaCode.inputMode = recovery ? "text" : "numeric";
    mfaCode.focus();
  });

  if (passkeyButton) passkeyButton.addEventListener("click", async () => {
    if (passkeyButton.disabled || submit.disabled) return;
    passkeyButton.disabled = true;
    submit.disabled = true;
    error.hidden = true;
    status.hidden = false;
    status.textContent = "Ожидаем подтверждение на вашем устройстве…";
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), 120000);
    try {
      const issued = await fetch("/api/v1/auth/form_token?purpose=login", {
        credentials: "include", cache: "no-store", headers: { Accept: "application/json" }, signal: timeout.signal,
      });
      const formToken = await jsonResponse(issued);
      if (!issued.ok || typeof formToken.form_token !== "string") {
        throw new Error(formToken.message || "Не удалось подготовить вход. Попробуйте ещё раз.");
      }
      const csrf = csrfCookie();
      if (!csrf) throw new Error("Не удалось подготовить защиту запроса. Обновите страницу.");
      const headers = { "Content-Type": "application/json", Accept: "application/json", "X-CSRFToken": csrf };
      const begun = await fetch("/api/v1/auth/passkeys/login/begin", {
        method: "POST", credentials: "include", cache: "no-store", headers, body: "{}", signal: timeout.signal,
      });
      const challenge = await jsonResponse(begun);
      if (!begun.ok) throw new Error(challenge.message || "Не удалось начать вход с Passkey.");
      const credential = await navigator.credentials.get({
        publicKey: passkeyOptions(challenge.request_options), signal: timeout.signal,
      });
      if (!credential) { status.hidden = true; return; }
      status.textContent = "Проверяем ключ…";
      const completed = await fetch("/api/v1/auth/passkeys/login/complete", {
        method: "POST", credentials: "include", cache: "no-store", headers,
        body: JSON.stringify({ credential: assertionJson(credential) }), signal: timeout.signal,
      });
      const result = await jsonResponse(completed);
      if (!completed.ok) throw new Error(result.message || "Не удалось войти с Passkey.");
      clearLegacyToken();
      window.location.replace(safeReturnPath(new URLSearchParams(window.location.search).get("next")));
    } catch (cause) {
      if (cause instanceof DOMException && ["NotAllowedError", "AbortError"].includes(cause.name)) {
        status.hidden = true;
      } else {
        showError(cause instanceof Error ? cause.message : "Не удалось войти с Passkey.");
      }
    } finally {
      clearTimeout(timer);
      passkeyButton.disabled = false;
      submit.disabled = false;
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    submit.disabled = true;
    if (passkeyButton) passkeyButton.disabled = true;
    error.hidden = true;
    status.hidden = false;
    status.textContent = "Проверяем данные…";
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), 30000);
    try {
      const issued = await fetch("/api/v1/auth/form_token?purpose=login", {
        credentials: "include",
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: timeout.signal,
      });
      const formToken = await jsonResponse(issued);
      if (!issued.ok || typeof formToken.form_token !== "string") {
        throw new Error(formToken.message || "Не удалось подготовить вход. Попробуйте ещё раз.");
      }
      const payload = {
        email: form.elements.email.value,
        password: form.elements.password.value,
        form_token: formToken.form_token,
      };
      if (!mfaFields.hidden && mfaCode.value.trim()) {
        payload[mfaMethod.value === "recovery" ? "recovery_code" : "mfa_code"] = mfaCode.value.trim();
      }
      const csrf = csrfCookie();
      const result = await fetch("/api/v1/auth/login", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...(csrf ? { "X-CSRFToken": csrf } : {}),
        },
        body: JSON.stringify(payload),
        signal: timeout.signal,
      });
      const body = await jsonResponse(result);
      if (!result.ok) {
        if (body.code === "MFA_REQUIRED") {
          mfaFields.hidden = false;
          mfaCode.required = true;
          mfaCode.focus();
          status.textContent = "Введите код подтверждения.";
          return;
        }
        throw new Error(body.message || "Не удалось войти. Проверьте данные и попробуйте ещё раз.");
      }
      // The transitional React account client gives an old explicit header
      // precedence over a newly issued cookie. Remove only its stale token.
      clearLegacyToken();
      window.location.replace(safeReturnPath(new URLSearchParams(window.location.search).get("next")));
    } catch (cause) {
      showError(cause && cause.name === "AbortError"
        ? "Превышено время ожидания. Попробуйте ещё раз."
        : cause instanceof Error ? cause.message : "Не удалось войти. Попробуйте ещё раз.");
    } finally {
      clearTimeout(timer);
      submit.disabled = false;
      if (passkeyButton) passkeyButton.disabled = false;
    }
  });

  void restoreLegacySession();
})();
