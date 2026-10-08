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
  const providers = [
    { id: "github", name: "GitHub", authorizeUrl: "https://github.com/login/oauth/authorize" },
    { id: "discord", name: "Discord", authorizeUrl: "https://discord.com/oauth2/authorize" },
    { id: "steam", name: "Steam", authorizeUrl: "https://steamcommunity.com/openid/login" },
  ].map(provider => ({ ...provider, enabled: false,
    button: document.getElementById(`${provider.id}-login`),
  }));
  const providerHint = document.getElementById("provider-hint");
  const loginQuery = new URLSearchParams(window.location.search);
  const reauth = ["provider-link", "provider-unlink"].includes(loginQuery.get("reauth"));
  const unlinkReview = loginQuery.get("reauth") === "provider-unlink" &&
    providers.find(provider => provider.id === loginQuery.get("provider"));
  const mfaProvider = providers.find(provider => provider.id === loginQuery.get("provider_mfa"));
  if (!form || !submit || !error || !status || !mfaFields || !mfaMethod || !mfaCode) return;
  const email = form.elements.email;
  const password = form.elements.password;
  const credentialFields = document.getElementById("credential-fields");
  const mfaBack = document.getElementById("mfa-back");
  let defaultAction = submit.textContent;
  let credentialsVersion = 0;
  let activeAttempt = null;

  function alternateDisabled(disabled) {
    if (passkeyButton) passkeyButton.disabled = disabled;
    for (const provider of providers) if (provider.button) provider.button.disabled = disabled || performance.now() < providerRetryAt;
  }

  function showProviderActions() {
    const hidden = Boolean(mfaProvider) || !mfaFields.hidden ||
      document.getElementById("session-choice")?.hidden === false;
    for (const provider of providers) {
      if (provider.button) {
        provider.button.hidden = !provider.enabled || hidden;
        provider.button.disabled = submit.disabled || performance.now() < providerRetryAt;
      }
    }
    if (providerHint) providerHint.hidden = hidden || !providers.some(provider => provider.enabled);
  }

  function credentialsChanged() {
    if (mfaProvider) return;
    credentialsVersion += 1;
    mfaFields.hidden = true;
    if (credentialFields) credentialFields.hidden = false;
    submit.textContent = defaultAction;
    mfaCode.required = false;
    mfaCode.value = "";
    error.hidden = true;
    status.hidden = true;
    showProviderActions();
    // Preparing a form token has no login side effect. A submitted login may
    // already have issued a cookie, so only its result can finish that attempt.
    if (activeAttempt && !activeAttempt.sending) {
      activeAttempt.controller.abort();
      activeAttempt = null;
      submit.disabled = false;
      alternateDisabled(false);
    }
  }
  mfaBack?.addEventListener("click", () => {
    if (mfaProvider) { void cancelProvider(); return; }
    if (!submit.disabled) { credentialsChanged(); password.focus(); }
  });
  email.addEventListener("input", credentialsChanged);
  password.addEventListener("input", credentialsChanged);

  if (!mfaProvider && passkeyButton && window.isSecureContext && window.PublicKeyCredential && navigator.credentials?.get) {
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

  const requestedNext = loginQuery.get("next");
  const returnPath = reauth ? "/account?section=security" +
    (unlinkReview ? `&review_unlink=${unlinkReview.id}` : "") : safeReturnPath(requestedNext);
  if (authContext && requestedNext && (returnPath.startsWith("/oauth/consent?") || returnPath.startsWith("/authorize?"))) {
    document.getElementById("login-title").textContent = "Войдите, чтобы продолжить";
    document.querySelector(".intro").textContent = "Вы открываете другой сервис через единый аккаунт UpdSpace ID.";
    submit.textContent = "Войти и продолжить";
    defaultAction = submit.textContent;
    authContext.textContent = "Сейчас вы входите только в UpdSpace ID. Если приложению нужны новые разрешения, мы покажем его название и запрошенные сведения на следующем шаге. Здесь вы ещё не даёте приложению доступ.";
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

  async function issueFormToken(signal) {
    const response = await fetch("/api/v1/auth/form_token?purpose=login", {
      credentials: "include", cache: "no-store", headers: { Accept: "application/json" }, signal,
    });
    const body = await jsonResponse(response);
    if (!response.ok || typeof body.form_token !== "string") {
      throw new Error(body.message || "Не удалось подготовить вход. Попробуйте ещё раз.");
    }
    return body.form_token;
  }

  const providerRetry = document.getElementById("provider-retry");
  const providerAccount = document.getElementById("provider-account");
  let providerStep = "loading";
  let providerBusy = false;
  let providerNext = null;
  let providerRetryAt = 0;
  let providerOutcomeUnknown = false;

  function providerControls(busy) {
    providerBusy = busy;
    submit.disabled = busy || providerStep !== "ready" || performance.now() < providerRetryAt;
    mfaCode.disabled = busy || providerStep !== "ready";
    mfaCode.required = providerStep === "ready";
    mfaMethod.disabled = busy || providerStep !== "ready";
    if (mfaBack) mfaBack.disabled = busy;
    if (providerRetry) providerRetry.disabled = busy;
    alternateDisabled(true);
    form.setAttribute("aria-busy", String(busy));
  }

  async function providerRequest(provider, suffix, payload) {
    const signal = AbortSignal.timeout(15000);
    const headers = { Accept: "application/json" };
    if (payload !== undefined) {
      if (!csrfCookie()) await issueFormToken(signal);
      const csrf = csrfCookie();
      if (!csrf) throw new Error("Не удалось подготовить защиту запроса. Обновите страницу.");
      headers["Content-Type"] = "application/json";
      headers["X-CSRFToken"] = csrf;
    }
    try {
      const response = await fetch(`/api/v1/auth/oauth/login/${provider.id}${suffix}`, {
        method: payload === undefined ? "GET" : "POST", credentials: "include", cache: "no-store",
        headers, signal, ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
      });
      return { response, body: await jsonResponse(response) };
    } catch (cause) {
      if (cause instanceof Error && payload !== undefined) cause.requestSent = true;
      throw cause;
    }
  }

  function providerRestart(message) {
    providerStep = "restart";
    if (providerAccount) providerAccount.hidden = false;
    showError(message);
  }

  function providerRateLimit(response) {
    const retry = response.headers.get("Retry-After");
    const seconds = retry && /^\d+$/u.test(retry) ? Number(retry) : 30;
    const duration = Math.min(seconds, 86400) * 1000;
    providerRetryAt = performance.now() + duration;
    showError(`Слишком много попыток. Повторите после ${new Date(Date.now() + duration).toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}.`);
    setTimeout(function release() {
      const remaining = providerRetryAt - performance.now();
      if (remaining > 0) { setTimeout(release, remaining); return; }
      if (mfaProvider) providerControls(providerBusy);
      else alternateDisabled(submit.disabled);
    }, Math.max(0, providerRetryAt - performance.now()));
  }

  async function loadProviderPending() {
    if (!mfaProvider || providerBusy) return;
    providerControls(true);
    error.hidden = true;
    status.hidden = false;
    status.textContent = `Проверяем вход через ${mfaProvider.name}…`;
    if (providerRetry) providerRetry.hidden = true;
    try {
      const { response, body } = await providerRequest(mfaProvider, "/pending");
      if ((response.status === 401 && body.code === "PROVIDER_FLOW_EXPIRED") || (response.ok && body.active === false)) {
        providerNext = null;
        providerRestart("Этот этап входа истёк, отменён или уже завершён. Проверьте аккаунт либо выберите другой способ входа.");
        return;
      }
      if (!response.ok) throw new Error(`Не удалось проверить вход через ${mfaProvider.name}. Повторите проверку.`);
      if (body.active !== true || !Array.isArray(body.methods) || !Number.isFinite(body.expires_at)) {
        throw new Error("Сервис вернул неожиданные параметры входа. Повторите проверку.");
      }
      providerNext = typeof body.next === "string" ? safeReturnPath(body.next) : null;
      if (providerOutcomeUnknown) {
        providerRestart("Результат отправленного кода пока не подтверждён. Проверьте аккаунт или отмените этот вход перед новой попыткой.");
        return;
      }
      const available = [...mfaMethod.options].filter(option => body.methods.includes(option.value === "recovery" ? "recovery_codes" : "totp"));
      if (body.restart_required === true || !available.length) {
        providerRestart("Для этого аккаунта нет доступного кода приложения или резервного кода. Выберите другой способ входа, например ключ доступа.");
        return;
      }
      for (const option of mfaMethod.options) option.disabled = option.hidden = !available.includes(option);
      if (!available.some(option => option.selected)) mfaMethod.value = available[0].value;
      mfaCode.autocomplete = mfaMethod.value === "recovery" ? "off" : "one-time-code";
      mfaCode.inputMode = mfaMethod.value === "recovery" ? "text" : "numeric";
      providerStep = "ready";
      document.getElementById("login-title").textContent = "Подтвердите вход";
      document.querySelector(".intro").textContent = "Завершите вход в связанный аккаунт UpdSpace ID.";
      const hint = document.getElementById("mfa-hint");
      if (hint) hint.textContent = `${mfaProvider.name} подтвердил связанный аккаунт. Введите код дополнительной защиты UpdSpace ID.`;
      const expiry = document.getElementById("provider-expiry");
      const date = new Date(body.expires_at * 1000);
      if (expiry && !Number.isNaN(date.valueOf())) {
        expiry.textContent = `Этот шаг действует до ${date.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })} по времени устройства.`;
        expiry.hidden = false;
      }
      status.hidden = true;
    } catch (cause) {
      providerStep = "loading";
      showError(cause instanceof Error ? cause.message : "Не удалось проверить вход. Повторите проверку.");
      if (providerRetry) providerRetry.hidden = false;
    } finally { providerControls(false); }
  }

  async function cancelProvider() {
    if (!mfaProvider || providerBusy) return;
    providerControls(true);
    error.hidden = true;
    status.hidden = false;
    status.textContent = `Отменяем вход через ${mfaProvider.name}…`;
    let leaving = false;
    try {
      const { response, body } = await providerRequest(mfaProvider, "/cancel", {});
      if (!response.ok || body.ok !== true) throw new Error("Не удалось подтвердить отмену. Повторите отмену, прежде чем выбрать другой способ входа.");
      leaving = true;
      window.location.replace(providerNext ? `/login?next=${encodeURIComponent(providerNext)}` : "/login");
    } catch {
      showError("Не удалось подтвердить отмену. Повторите отмену, прежде чем выбрать другой способ входа.");
    } finally { if (!leaving) providerControls(false); }
  }

  async function completeProvider() {
    if (submit.disabled || providerStep !== "ready") return;
    const code = mfaCode.value.trim();
    if (!code) { mfaCode.setAttribute("aria-invalid", "true"); showError("Введите код подтверждения."); return; }
    const payload = { [mfaMethod.value === "recovery" ? "recovery_code" : "mfa_code"]: code };
    providerControls(true);
    error.hidden = true;
    status.hidden = false;
    status.textContent = "Подтверждаем вход…";
    let leaving = false;
    try {
      const { response, body } = await providerRequest(mfaProvider, "/complete", payload);
      if (response.status === 401 && body.code === "INVALID_MFA") {
        mfaCode.setAttribute("aria-invalid", "true");
        showError("Неверный код. Проверьте его и попробуйте ещё раз.");
      } else if (response.status === 401 && body.code === "PROVIDER_FLOW_EXPIRED") {
        providerRestart("Этот этап входа истёк, отменён или уже завершён. Проверьте аккаунт либо выберите другой способ входа.");
      } else if (response.status === 429) {
        providerRateLimit(response);
      } else if (response.ok && typeof body.next === "string") {
        clearLegacyToken();
        leaving = true;
        window.location.replace(safeReturnPath(body.next));
      } else if (!response.ok && response.status < 500) {
        providerRestart("Не удалось подтвердить вход. Выберите другой способ входа или начните заново.");
      } else { throw Object.assign(new Error("Unknown result"), { requestSent: true }); }
    } catch (cause) {
      if (cause?.requestSent) {
        providerOutcomeUnknown = true;
        providerRestart("Результат входа неизвестен: запрос мог выполниться. Проверьте аккаунт; не отправляйте код повторно без проверки.");
        if (providerRetry) providerRetry.hidden = false;
      } else showError("Не удалось подготовить защиту запроса. Повторите попытку или обновите страницу.");
    } finally { if (!leaving) providerControls(false); }
  }

  for (const provider of providers) provider.button?.addEventListener("click", async () => {
    if (!provider.enabled || mfaProvider || submit.disabled || provider.button.disabled) return;
    submit.disabled = true;
    alternateDisabled(true);
    email.readOnly = password.readOnly = true;
    error.hidden = true;
    status.hidden = false;
    status.textContent = `Открываем ${provider.name}…`;
    let leaving = false;
    try {
      const formToken = await issueFormToken(AbortSignal.timeout(15000));
      const { response, body } = await providerRequest(provider, "", { form_token: formToken, next: returnPath });
      if (response.status === 429) { providerRateLimit(response); return; }
      if (body.code === "INVALID_REDIRECT") throw new Error(`${provider.name} пока не поддерживает этот переход. Войдите с паролем или ключом доступа.`);
      if (!response.ok) throw new Error(`Вход через ${provider.name} сейчас недоступен. Попробуйте позже или выберите другой способ.`);
      const target = new URL(body.authorize_url);
      if (body.method !== "GET" || target.origin + target.pathname !== provider.authorizeUrl || target.username || target.password) {
        throw new Error(`Сервис вернул неверный адрес ${provider.name}. Вход остановлен.`);
      }
      clearLegacyToken();
      leaving = true;
      window.location.assign(target.href);
    } catch (cause) {
      showError(cause instanceof Error ? cause.message : `Не удалось начать вход через ${provider.name}.`);
    } finally {
      if (!leaving) { submit.disabled = false; alternateDisabled(false); email.readOnly = password.readOnly = false; }
    }
  });

  providerRetry?.addEventListener("click", () => { void loadProviderPending(); });

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
    if (reauth) return;
    const next = new URLSearchParams(window.location.search).get("next");
    const token = legacyToken();
    if (!next || !token) return;
    if (token.length > 512 || !/^[\x21-\x7e]+$/u.test(token)) {
      clearLegacyToken();
      return;
    }
    submit.disabled = true;
    alternateDisabled(true);
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
      alternateDisabled(false);
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
    if (mfaProvider || passkeyButton.disabled || submit.disabled) return;
    alternateDisabled(true);
    submit.disabled = true;
    error.hidden = true;
    status.hidden = false;
    status.textContent = "Ожидаем подтверждение на вашем устройстве…";
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(), 120000);
    try {
      await issueFormToken(timeout.signal);
      const csrf = csrfCookie();
      if (!csrf) throw new Error("Не удалось подготовить защиту запроса. Обновите страницу.");
      const headers = { "Content-Type": "application/json", Accept: "application/json", "X-CSRFToken": csrf };
      const begun = await fetch("/api/v1/auth/passkeys/login/begin", {
        method: "POST", credentials: "include", cache: "no-store", headers, body: "{}", signal: timeout.signal,
      });
      const challenge = await jsonResponse(begun);
      if (!begun.ok) throw new Error(challenge.message || "Не удалось начать вход с ключом доступа.");
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
      if (!completed.ok) throw new Error(result.message || "Не удалось войти с ключом доступа.");
      clearLegacyToken();
      window.location.replace(returnPath);
    } catch (cause) {
      if (cause instanceof DOMException && ["NotAllowedError", "AbortError"].includes(cause.name)) {
        status.hidden = true;
      } else {
        showError(cause instanceof Error ? cause.message : "Не удалось войти с ключом доступа.");
      }
    } finally {
      clearTimeout(timer);
      alternateDisabled(false);
      submit.disabled = false;
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (mfaProvider) { await completeProvider(); return; }
    if (submit.disabled) return;
    submit.disabled = true;
    alternateDisabled(true);
    error.hidden = true;
    status.hidden = false;
    status.textContent = "Проверяем данные…";
    const timeout = new AbortController();
    const attempt = {
      controller: timeout,
      version: credentialsVersion,
      email: email.value,
      password: password.value,
      sending: false,
    };
    activeAttempt = attempt;
    const timer = setTimeout(() => timeout.abort(), 30000);
    try {
      const formToken = await issueFormToken(timeout.signal);
      if (activeAttempt !== attempt || attempt.version !== credentialsVersion) return;
      const payload = {
        email: attempt.email,
        password: attempt.password,
        form_token: formToken,
      };
      if (!mfaFields.hidden && mfaCode.value.trim()) {
        payload[mfaMethod.value === "recovery" ? "recovery_code" : "mfa_code"] = mfaCode.value.trim();
      }
      const csrf = csrfCookie();
      attempt.sending = true;
      email.readOnly = true;
      password.readOnly = true;
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
        if (activeAttempt !== attempt || attempt.version !== credentialsVersion) return;
        if (body.code === "MFA_REQUIRED") {
          mfaFields.hidden = false;
          showProviderActions();
          if (credentialFields) credentialFields.hidden = true;
          submit.textContent = "Подтвердить вход";
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
      window.location.replace(returnPath);
    } catch (cause) {
      if (activeAttempt !== attempt || attempt.version !== credentialsVersion) return;
      showError(cause && cause.name === "AbortError"
        ? "Превышено время ожидания. Попробуйте ещё раз."
        : cause instanceof Error ? cause.message : "Не удалось войти. Попробуйте ещё раз.");
    } finally {
      clearTimeout(timer);
      if (activeAttempt === attempt) {
        activeAttempt = null;
        email.readOnly = false;
        password.readOnly = false;
        submit.disabled = false;
        alternateDisabled(false);
      }
    }
  });

  if (mfaProvider) {
    email.disabled = password.disabled = true;
    email.required = password.required = false;
    if (credentialFields) credentialFields.hidden = true;
    if (passkeyButton) passkeyButton.hidden = true;
    const links = document.querySelector(".auth-links");
    if (links) links.hidden = true;
    mfaFields.hidden = false;
    if (mfaBack) mfaBack.textContent = "Другой способ входа";
    submit.textContent = "Подтвердить вход";
    document.getElementById("login-title").textContent = `Вход через ${mfaProvider.name}`;
    document.querySelector(".intro").textContent = "Проверяем сохранённый шаг входа в этом браузере.";
    const hint = document.getElementById("mfa-hint");
    if (hint) hint.textContent = "Дождитесь проверки, прежде чем вводить код.";
    void loadProviderPending();
  } else {
    void restoreLegacySession();
    const providerErrors = {
      INVALID_STATE: "Срок входа через внешний сервис истёк или запрос не соответствует этому браузеру. Начните заново.",
      PROVIDER_DENIED: "Вы отменили вход через внешний сервис. Можно попробовать снова или выбрать другой способ.",
      ACCOUNT_NOT_LINKED: "К этому внешнему сервису не подключён аккаунт UpdSpace ID. Войдите другим способом.",
      IDENTITY_CONFLICT: "Не удалось однозначно определить связанный аккаунт. Войдите другим способом.",
      LOGIN_RATE_LIMITED: "Слишком много попыток. Подождите и начните вход заново.",
    };
    if (loginQuery.has("provider_error")) {
      const code = loginQuery.get("provider_error");
      showError(Object.hasOwn(providerErrors, code) ? providerErrors[code] : "Вход через внешний сервис сейчас недоступен. Попробуйте позже или выберите другой способ.");
    }
    if (providers.some(provider => provider.button)) fetch("/api/v1/auth/oauth/providers", {
      credentials: "include", cache: "no-store", signal: AbortSignal.timeout(8000),
    }).then(response => response.ok ? response.json() : null).then(body => {
      for (const provider of providers) {
        provider.enabled = Array.isArray(body?.providers) && body.providers.some(item => item?.id === provider.id && item.login_enabled === true);
      }
      showProviderActions();
    }).catch(() => {});
  }
  if (!window.location.search) {
    let touched = false;
    form.addEventListener("input", () => { touched = true; }, { once: true });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    fetch("/api/v1/auth/me", { credentials: "include", cache: "no-store", signal: controller.signal })
      .then(response => response.ok ? response.json() : null)
      .then(body => {
        if (!body?.user || touched || activeAttempt || submit.disabled || !mfaFields.hidden) return;
        const choice = document.getElementById("session-choice");
        if (!choice) return;
        document.getElementById("session-name").textContent = body.user.email || body.user.username || "Ваш аккаунт";
        choice.hidden = false;
        form.hidden = true;
        showProviderActions();
        const passkeyVisible = passkeyButton && !passkeyButton.hidden;
        if (passkeyButton) passkeyButton.hidden = true;
        document.getElementById("choose-another").addEventListener("click", () => {
          choice.hidden = true;
          form.hidden = false;
          showProviderActions();
          if (passkeyButton) passkeyButton.hidden = !passkeyVisible;
          email.focus();
        });
      }).catch(() => {}).finally(() => clearTimeout(timer));
  }
})();
