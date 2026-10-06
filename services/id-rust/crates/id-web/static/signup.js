(() => {
  "use strict";

  const form = document.getElementById("signup-form");
  const submit = document.getElementById("submit");
  const status = document.getElementById("status");
  const error = document.getElementById("error");
  if (!form || !submit || !status || !error) return;

  const minor = form.elements.namedItem("is-minor");
  const birthDate = form.elements.namedItem("birth-date");
  const guardianFields = document.getElementById("guardian-fields");
  const guardianEmail = form.elements.namedItem("guardian-email");
  const guardianConsent = form.elements.namedItem("guardian-consent");

  function underEighteen(value) {
    if (!value) return false;
    const born = new Date(`${value}T00:00:00`);
    if (Number.isNaN(born.valueOf()) || born > new Date()) return false;
    const threshold = new Date();
    threshold.setFullYear(threshold.getFullYear() - 18);
    return born > threshold;
  }

  function updateGuardianFields() {
    const required = minor.checked || underEighteen(birthDate.value);
    guardianFields.hidden = !required;
    guardianEmail.required = required;
    guardianConsent.required = required;
  }

  minor.addEventListener("change", updateGuardianFields);
  birthDate.addEventListener("change", updateGuardianFields);
  updateGuardianFields();

  function safeReturnPath(value) {
    if (!value || /[\\\u0000-\u0020\u007f]/u.test(value)) return "/account";
    try {
      const target = new URL(value, window.location.origin);
      if (target.origin !== window.location.origin) return "/account";
      if (!["/", "/account", "/authorize", "/oauth/consent"].includes(target.pathname)) return "/account";
      if (target.searchParams.has("next")) return "/account";
      return target.pathname + target.search + target.hash;
    } catch { return "/account"; }
  }

  const returnPath = safeReturnPath(new URLSearchParams(window.location.search).get("next"));
  const loginLink = document.querySelector('.signup-card a[href="/login"]');
  if (loginLink) loginLink.href = `/login?next=${encodeURIComponent(returnPath)}`;

  function show(message, failed = false) {
    const target = failed ? error : status;
    target.textContent = message;
    target.hidden = false;
    (failed ? status : error).hidden = true;
  }

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  async function json(response) {
    try { return await response.json(); }
    catch { throw new Error("Сервис вернул неожиданный ответ. Попробуйте ещё раз."); }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    const fields = form.elements;
    const password = fields.namedItem("password").value;
    if (password !== fields.namedItem("confirmation").value) {
      show("Пароли не совпадают.", true);
      return;
    }
    if (!fields.namedItem("consent-data").checked) {
      show("Требуется согласие на обработку персональных данных.", true);
      return;
    }
    updateGuardianFields();
    if (guardianFields.hidden === false && (!guardianEmail.value || !guardianConsent.checked)) {
      show("Для пользователей младше 18 лет нужны email и согласие родителя или опекуна.", true);
      return;
    }
    submit.disabled = true;
    form.setAttribute("aria-busy", "true");
    show("Создаём аккаунт…");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      const issued = await fetch("/api/v1/auth/form_token?purpose=register", {
        credentials: "include", cache: "no-store", headers: { Accept: "application/json" }, signal: controller.signal,
      });
      const token = await json(issued);
      if (!issued.ok || typeof token.form_token !== "string") {
        throw new Error(token.message || "Не удалось подготовить регистрацию. Попробуйте ещё раз.");
      }
      const csrf = csrfCookie();
      if (!csrf) throw new Error("Не удалось подготовить защиту запроса. Обновите страницу.");
      const response = await fetch("/api/v1/auth/signup", {
        method: "POST", credentials: "include", cache: "no-store", signal: controller.signal,
        headers: { "Content-Type": "application/json", Accept: "application/json", "X-CSRFToken": csrf },
        body: JSON.stringify({
          username: fields.namedItem("username").value.trim() || undefined,
          email: fields.namedItem("email").value.trim(),
          password,
          language: fields.namedItem("language").value,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || undefined,
          consent_data_processing: true,
          consent_marketing: fields.namedItem("consent-marketing").checked,
          is_minor: minor.checked || underEighteen(birthDate.value),
          guardian_email: !guardianFields.hidden ? guardianEmail.value.trim() : undefined,
          guardian_consent: !guardianFields.hidden && guardianConsent.checked,
          birth_date: birthDate.value || undefined,
          form_token: token.form_token,
        }),
      });
      const result = await json(response);
      if (!response.ok) throw new Error(result.message || "Не удалось создать аккаунт. Попробуйте ещё раз.");
      if (!result.verification_required) {
        window.location.replace(returnPath);
        return;
      }
      fields.namedItem("password").value = "";
      fields.namedItem("confirmation").value = "";
      form.hidden = true;
      show("Аккаунт создан. Проверьте почту и подтвердите адрес, затем войдите.");
      const link = document.createElement("a");
      link.href = `/verify-email?next=${encodeURIComponent(returnPath)}`;
      link.textContent = "Подтвердить адрес или запросить письмо повторно";
      status.append(document.createTextNode(" "), link);
    } catch (cause) {
      const message = cause && cause.name === "AbortError"
        ? "Превышено время ожидания. Проверьте почту или повторите попытку позже."
        : cause instanceof Error ? cause.message : "Не удалось создать аккаунт.";
      show(message, true);
    } finally {
      clearTimeout(timeout);
      submit.disabled = false;
      form.removeAttribute("aria-busy");
    }
  });
})();
