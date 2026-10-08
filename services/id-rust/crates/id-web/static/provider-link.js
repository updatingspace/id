(() => {
  "use strict";
  const panel = document.getElementById("provider-links");
  if (!panel) return;
  const account = document.getElementById("provider-link-account");
  const status = document.getElementById("provider-link-status");
  const error = document.getElementById("provider-link-error");
  const reauth = document.getElementById("provider-link-reauth");
  const refresh = document.getElementById("provider-link-refresh");
  const cancel = document.getElementById("provider-link-cancel");
  const providers = [
    { id: "github", url: "https://github.com/login/oauth/authorize" },
    { id: "discord", url: "https://discord.com/oauth2/authorize" },
    { id: "steam", url: "https://steamcommunity.com/openid/login" },
  ].map(provider => ({ ...provider, enabled: null,
    row: panel.querySelector(`[data-link-provider="${provider.id}"]`),
  }));
  const query = new URLSearchParams(window.location.search);
  const linkedHint = providers.find(provider => provider.id === query.get("provider_linked"));
  const callbackError = query.get("provider_link_error");
  const messages = {
    INVALID_STATE: "Попытка подключения истекла или не соответствует этому браузеру. Проверьте связи перед новой попыткой.",
    PROVIDER_DENIED: "Подключение отменено на стороне внешнего сервиса.",
    PROVIDER_UNAVAILABLE: "Внешний сервис сейчас недоступен. Попробуйте позже.",
    IDENTITY_CONFLICT: "Этот внешний аккаунт нельзя подключить: связь уже существует или требует проверки. Существующие связи не заменяются.",
    AUTHENTICATION_REQUIRED: "Сессия завершена. Войдите заново, затем выберите сервис для подключения.",
    REAUTH_REQUIRED: "Перед подключением подтвердите личность повторным входом. После входа выберите сервис ещё раз.",
    LOGIN_RATE_LIMITED: "Слишком много попыток. Подождите перед новым подключением.",
    SERVICE_UNAVAILABLE: "Результат подключения пока не подтверждён. Обновите сведения о связях.",
  };
  let user = panel.dataset.providersKnown === "true" ? {
    email: account.textContent.trim(),
    oauth_providers: providers.filter(provider => provider.row.dataset.linked === "true").map(provider => provider.id),
  } : null;
  let busy = false;
  let pending = null;
  let retryAt = 0;
  let needsAuth = false;
  refresh.hidden = false;

  function showError(code) {
    error.textContent = Object.hasOwn(messages, code) ? messages[code] : "Не удалось проверить или подключить внешний аккаунт. Обновите сведения и попробуйте позже.";
    if (pending) error.textContent += " После проверки отмените попытку, прежде чем начать новую.";
    error.hidden = false;
    status.hidden = true;
    needsAuth = code === "REAUTH_REQUIRED" || code === "AUTHENTICATION_REQUIRED";
    reauth.hidden = !needsAuth;
  }

  function render() {
    panel.hidden = !linkedHint && !callbackError &&
      !providers.some(provider => provider.enabled || user?.oauth_providers.includes(provider.id));
    account.textContent = user?.email || user?.username || "Не удалось определить";
    panel.setAttribute("aria-busy", String(busy));
    refresh.disabled = busy;
    cancel.hidden = !pending;
    cancel.disabled = busy || performance.now() < retryAt;
    for (const provider of providers) {
      const linked = user?.oauth_providers.includes(provider.id);
      const review = provider.row.querySelector("[data-link-review]");
      provider.row.hidden = !provider.enabled && !linked;
      provider.row.querySelector("[data-link-state]").textContent = !user ? "Состояние не подтверждено" :
        linked ? (provider.enabled === false ? "Связан · вход сейчас недоступен" : "Связан") : "Не подключён";
      review.hidden = !user || linked || !provider.enabled;
      if (review.hidden) review.open = false;
      provider.row.querySelector("[data-link-begin]").disabled = busy || !user || linked ||
        !provider.enabled || needsAuth || Boolean(pending) || performance.now() < retryAt;
    }
  }

  function csrfCookie() {
    const entry = document.cookie.split("; ").find(item => item.startsWith("csrftoken="));
    try { return entry ? decodeURIComponent(entry.slice(10)) : ""; }
    catch { return ""; }
  }

  async function request(path, mutation = false) {
    const signal = AbortSignal.timeout(15000);
    const headers = { Accept: "application/json" };
    if (mutation) {
      if (!csrfCookie()) await request("/api/v1/auth/form_token?purpose=login");
      const csrf = csrfCookie();
      if (!csrf) throw new Error("CSRF unavailable");
      headers["Content-Type"] = "application/json";
      headers["X-CSRFToken"] = csrf;
    }
    try {
      const response = await fetch(path, {
        method: mutation ? "POST" : "GET", credentials: "include", cache: "no-store",
        headers, signal, ...(mutation ? { body: "{}" } : {}),
      });
      return { response, body: await response.json() };
    } catch (cause) {
      throw Object.assign(new Error("Request failed"), { requestSent: mutation, cause });
    }
  }

  async function readUser() {
    user = null;
    const { response, body } = await request("/api/v1/auth/me");
    if (response.status === 401 || (response.ok && body.user === null)) {
      throw Object.assign(new Error("Sign in required"), { code: "AUTHENTICATION_REQUIRED" });
    }
    if (!response.ok || !body.user || !Array.isArray(body.user.oauth_providers) ||
        !body.user.oauth_providers.every(value => typeof value === "string") ||
        !(typeof body.user.email === "string" && body.user.email || typeof body.user.username === "string" && body.user.username)) {
      throw new Error("Profile unavailable");
    }
    user = body.user;
  }

  function cooldown(response) {
    const retry = response.headers.get("Retry-After");
    const seconds = retry && /^\d+$/u.test(retry) ? Math.min(Number(retry), 86400) : 30;
    retryAt = performance.now() + seconds * 1000;
    showError("LOGIN_RATE_LIMITED");
    error.textContent += ` Повторите после ${new Date(Date.now() + seconds * 1000).toLocaleTimeString("ru")}.`;
    setTimeout(function release() {
      const remaining = retryAt - performance.now();
      if (remaining > 0) { setTimeout(release, remaining); return; }
      render();
    }, Math.max(0, retryAt - performance.now()));
  }

  async function load(refreshProfile = false) {
    if (busy) return;
    busy = true;
    needsAuth = false;
    error.hidden = status.hidden = reauth.hidden = true;
    render();
    try {
      const [profile, capability] = await Promise.allSettled([
        refreshProfile ? readUser() : Promise.resolve(), request("/api/v1/auth/oauth/providers"),
      ]);
      for (const provider of providers) {
        const result = capability.status === "fulfilled" ? capability.value : null;
        provider.enabled = result?.response.ok && Array.isArray(result.body?.providers) ?
          result.body.providers.some(item => item?.id === provider.id && item.login_enabled === true) : null;
      }
      if (profile.status === "rejected") throw profile.reason;
      if (!user) throw new Error("Profile unavailable");
      if (linkedHint && !user.oauth_providers.includes(linkedHint.id)) showError("SERVICE_UNAVAILABLE");
      else if (callbackError) showError(callbackError);
      else if (pending) showError("SERVICE_UNAVAILABLE");
      else if (refreshProfile || linkedHint) {
        status.textContent = "Связи проверены по текущему аккаунту.";
        status.hidden = false;
      }
      if (capability.status === "rejected" || !capability.value.response.ok) showError("PROVIDER_UNAVAILABLE");
    } catch (cause) { showError(cause?.code); }
    finally { busy = false; render(); }
  }

  for (const provider of providers) provider.row.querySelector("[data-link-begin]").addEventListener("click", async () => {
    if (busy || !user || !provider.enabled || needsAuth || pending || performance.now() < retryAt || user.oauth_providers.includes(provider.id)) return;
    busy = true;
    error.hidden = status.hidden = true;
    render();
    const previousAccount = user.email || user.username;
    let leaving = false;
    try {
      await readUser();
      if ((user.email || user.username) !== previousAccount || user.oauth_providers.includes(provider.id)) {
        for (const item of providers) item.row.querySelector("[data-link-review]").open = false;
        status.textContent = "Сведения об аккаунте изменились. Проверьте текущий аккаунт и выберите действие ещё раз.";
        status.hidden = false;
        status.focus();
        return;
      }
      const { response, body } = await request(`/api/v1/auth/oauth/link/${provider.id}`, true);
      if (response.status === 429) { cooldown(response); return; }
      if (!response.ok && response.status < 500) { showError(body.code); return; }
      // A missing or invalid response may follow a committed begin; cancel it before another mutation.
      pending = provider;
      if (!response.ok) throw Object.assign(new Error("Unknown result"), { requestSent: true });
      const target = new URL(body.authorize_url);
      if (body.method !== "GET" || target.origin + target.pathname !== provider.url || target.username || target.password) {
        throw new Error("Invalid provider URL");
      }
      leaving = true;
      window.location.assign(target.href);
    } catch (cause) {
      if (cause?.requestSent) pending = provider;
      showError(pending ? "SERVICE_UNAVAILABLE" : cause?.code);
    } finally { if (!leaving) { busy = false; render(); } }
  });

  cancel.addEventListener("click", async () => {
    if (busy || !pending || performance.now() < retryAt) return;
    busy = true;
    render();
    try {
      const { response, body } = await request(`/api/v1/auth/oauth/login/${pending.id}/cancel`, true);
      if (response.status === 429) { cooldown(response); return; }
      if (!response.ok || body.ok !== true) { showError("SERVICE_UNAVAILABLE"); return; }
      pending = null;
      error.hidden = true;
      status.textContent = "Попытка отменена. Можно выбрать сервис заново.";
      status.hidden = false;
      status.focus();
    } catch { showError("SERVICE_UNAVAILABLE"); }
    finally { busy = false; render(); }
  });
  refresh.addEventListener("click", () => { void load(true); });
  void load();
})();
