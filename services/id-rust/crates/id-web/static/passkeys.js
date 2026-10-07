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
      const uncertain = (failure) => {
        const error = new Error("Результат неизвестен. Возможно, ключ уже добавлен, а резервные коды не показаны. Не повторяйте добавление: сначала обновите список ключей и проверьте резервные коды.");
        error.uncertainPasskey = true;
        error.cause = failure;
        return error;
      };
      let response;
      try {
        response = await fetch(path, {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
      } catch (failure) {
        throw path.endsWith("/complete") ? uncertain(failure) : failure;
      }
      let body;
      try {
        body = await response.json();
      } catch (failure) {
        throw path.endsWith("/complete") ? uncertain(failure) : failure;
      }
      if (!response.ok) {
        if (path.endsWith("/complete") && response.status >= 500) throw uncertain();
        throw new Error(typeof body.message === "string" ? body.message : "Не удалось изменить ключ доступа.");
      }
      return body;
    } finally {
      clearTimeout(timer);
    }
  }

  const register = document.getElementById("passkey-register");
  const review = document.getElementById("passkey-review");
  const nameInput = document.getElementById("passkey-name");
  const message = document.getElementById("passkey-register-message");
  const recovery = document.getElementById("passkey-recovery");
  const recoveryList = document.getElementById("passkey-recovery-codes");
  let codesVisible = false;
  if (register && review && nameInput && message && recovery && recoveryList) {
    review.addEventListener("click", () => window.location.reload());
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
      let needsReview = false;
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
        if (failure?.uncertainPasskey) {
          needsReview = true;
          review.hidden = false;
          const empty = document.getElementById("passkeys-empty");
          if (empty) empty.hidden = true;
          error.textContent = failure.message;
          review.focus();
        } else if (failure?.name === "NotAllowedError" || failure?.name === "AbortError") {
          error.textContent = "Создание ключа отменено или ответ не подтверждён. Обновите список перед повтором.";
        } else {
          error.textContent = failure instanceof Error ? failure.message : "Не удалось добавить ключ доступа.";
        }
        error.hidden = false;
      } finally {
        register.disabled = needsReview;
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
    const button = event.target.closest("button[data-passkey-rename],button[data-passkey-delete],button[data-passkey-rename-save],button[data-passkey-delete-confirm],button[data-passkey-cancel]");
    if (!button || button.disabled) return;
    const row = button.closest(".passkey-row");
    if (!row) return;
    const editor = row.querySelector("[data-passkey-editor]");
    const deletion = row.querySelector("[data-passkey-delete-review]");
    if (button.hasAttribute("data-passkey-rename")) {
      error.hidden = true;
      deletion.hidden = true;
      editor.hidden = false;
      const input = editor.querySelector("input");
      input.value = row.querySelector("strong").textContent;
      input.focus();
    } else if (button.hasAttribute("data-passkey-delete")) {
      error.hidden = true;
      editor.hidden = true;
      deletion.hidden = false;
      deletion.querySelector("[data-passkey-cancel]").focus();
    } else if (button.hasAttribute("data-passkey-cancel")) {
      const wasDeletion = !deletion.hidden;
      editor.hidden = true;
      deletion.hidden = true;
      row.querySelector(wasDeletion ? "[data-passkey-delete]" : "[data-passkey-rename]").focus();
    } else if (button.hasAttribute("data-passkey-rename-save")) {
      const name = editor.querySelector("input").value.trim();
      if (!name || [...name].length > 80) {
        error.textContent = "Введите название ключа длиной до 80 символов.";
        error.hidden = false;
        editor.querySelector("input").focus();
        return;
      }
      void submit(button, "/api/v1/auth/passkeys/rename", { authenticator_id: button.dataset.passkeyRenameSave, new_name: name });
    } else if (button.hasAttribute("data-passkey-delete-confirm")) {
      void submit(button, "/api/v1/auth/passkeys/delete", { ids: [button.dataset.passkeyDeleteConfirm] });
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const row = event.target.closest(".passkey-row");
    if (!row) return;
    const editor = row.querySelector("[data-passkey-editor]");
    const deletion = row.querySelector("[data-passkey-delete-review]");
    if (editor.hidden && deletion.hidden) return;
    const wasDeletion = !deletion.hidden;
    editor.hidden = true;
    deletion.hidden = true;
    row.querySelector(wasDeletion ? "[data-passkey-delete]" : "[data-passkey-rename]").focus();
  });
})();
