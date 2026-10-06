(() => {
  "use strict";
  const error = document.getElementById("passkey-error");
  if (!error) return;

  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  function decodeBase64Url(value) {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function encodeBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function creationOptions(input) {
    const options = input?.publicKey ?? input;
    if (!options || typeof options.challenge !== "string" || typeof options.user?.id !== "string") {
      throw new Error("Сервер не вернул параметры ключа доступа.");
    }
    return {
      ...options,
      challenge: decodeBase64Url(options.challenge),
      user: { ...options.user, id: decodeBase64Url(options.user.id) },
      excludeCredentials: options.excludeCredentials?.map((credential) => ({
        ...credential,
        id: decodeBase64Url(credential.id),
      })),
    };
  }

  function serializeAttestation(credential) {
    const response = credential.response;
    if (!response?.attestationObject || !response?.clientDataJSON) {
      throw new Error("Браузер не вернул данные нового ключа.");
    }
    return {
      id: credential.id,
      rawId: encodeBase64Url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment,
      response: {
        clientDataJSON: encodeBase64Url(response.clientDataJSON),
        attestationObject: encodeBase64Url(response.attestationObject),
        transports: response.getTransports?.() ?? [],
      },
    };
  }

  async function post(path, payload) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(path, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(typeof body.message === "string" ? body.message : "Не удалось изменить ключ доступа.");
      }
      return body;
    } finally {
      clearTimeout(timer);
    }
  }

  const register = document.getElementById("passkey-register");
  const nameInput = document.getElementById("passkey-name");
  const message = document.getElementById("passkey-register-message");
  const recovery = document.getElementById("passkey-recovery");
  const recoveryList = document.getElementById("passkey-recovery-codes");
  let codesVisible = false;
  if (register && nameInput && message && recovery && recoveryList) {
    register.addEventListener("click", async () => {
      if (register.disabled) return;
      if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials?.create) {
        error.textContent = "Этот браузер не поддерживает ключи доступа. Используйте пароль и MFA.";
        error.hidden = false;
        return;
      }
      const name = nameInput.value.trim();
      if (!name || [...name].length > 80) {
        error.textContent = "Введите название ключа длиной до 80 символов.";
        error.hidden = false;
        return;
      }
      register.disabled = true;
      error.hidden = true;
      try {
        const begin = await post("/api/v1/auth/passkeys/begin", { passwordless: true });
        const credential = await navigator.credentials.create({
          publicKey: creationOptions(begin.creation_options),
        });
        if (!credential) return;
        const result = await post("/api/v1/auth/passkeys/complete", {
          name,
          credential: serializeAttestation(credential),
        });
        if (Array.isArray(result.recovery_codes) && result.recovery_codes.length) {
          if (result.recovery_codes.some((code) => typeof code !== "string" || !/^\d{8}$/.test(code))) {
            throw new Error("Сервер вернул неверный набор резервных кодов. Проверьте состояние MFA.");
          }
          for (const code of result.recovery_codes) {
            const item = document.createElement("li");
            item.textContent = code;
            recoveryList.append(item);
          }
          recovery.hidden = false;
          codesVisible = true;
          message.textContent = "Ключ добавлен. Сохраните резервные коды перед уходом со страницы.";
          message.hidden = false;
          register.hidden = true;
        } else {
          window.location.reload();
        }
      } catch (failure) {
        if (failure?.name === "NotAllowedError" || failure?.name === "AbortError") {
          error.textContent = "Создание ключа отменено или ответ не подтверждён. Обновите список перед повтором.";
        } else {
          error.textContent = failure instanceof Error ? failure.message : "Не удалось добавить ключ доступа.";
        }
        error.hidden = false;
      } finally {
        register.disabled = false;
      }
    });
  }

  window.addEventListener("beforeunload", (event) => {
    if (!codesVisible) return;
    event.preventDefault();
    event.returnValue = "";
  });

  async function submit(button, path, payload) {
    button.disabled = true;
    error.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(path, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      const body = await response.json();
      if (!response.ok || body.ok !== true) {
        throw new Error(typeof body.message === "string" ? body.message : "Не удалось изменить ключ доступа.");
      }
      window.location.reload();
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить результат. Обновите страницу и проверьте список ключей.";
      error.hidden = false;
      button.disabled = false;
    } finally {
      clearTimeout(timer);
    }
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-passkey-rename],button[data-passkey-delete]");
    if (!button || button.disabled) return;
    if (button.hasAttribute("data-passkey-rename")) {
      const id = button.dataset.passkeyRename;
      const name = window.prompt("Новое название ключа доступа", button.closest(".session-row")?.querySelector("strong")?.textContent || "");
      if (name === null || !name.trim()) return;
      void submit(button, "/api/v1/auth/passkeys/rename", { authenticator_id: id, new_name: name.trim() });
    } else {
      const id = button.dataset.passkeyDelete;
      if (!window.confirm("Удалить этот ключ доступа? Если это последний способ MFA, резервные коды также будут удалены.")) return;
      void submit(button, "/api/v1/auth/passkeys/delete", { ids: [id] });
    }
  });
})();
