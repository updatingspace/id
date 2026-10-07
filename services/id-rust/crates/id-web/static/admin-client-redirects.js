(() => {
  "use strict";
  const editor = document.getElementById("redirect-editor");
  if (!editor) return;
  const textarea = document.getElementById("new-redirects");
  const reviewButton = document.getElementById("client-redirect-review");
  const confirm = document.getElementById("client-redirect-confirm");
  const diff = document.getElementById("client-redirect-diff");
  const password = document.getElementById("client-redirect-password");
  const save = document.getElementById("client-redirect-save");
  const cancel = document.getElementById("client-redirect-cancel");
  const message = document.getElementById("client-redirect-message");
  const clientId = editor.dataset.clientId;
  let revision = editor.dataset.revision;
  let current;
  try { current = JSON.parse(editor.dataset.current); }
  catch { current = null; }
  let reviewed = null;
  const csrfCookie = () => {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  };
  const show = (text, alert = false) => {
    message.textContent = text;
    message.hidden = false;
    message.setAttribute("role", alert ? "alert" : "status");
    message.focus();
  };
  const lines = () => textarea.value.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  const valid = (uris) => {
    if (!uris.length || uris.length > 100 || new Set(uris).size !== uris.length) return false;
    if (uris.reduce((length, uri) => length + uri.length, 0) > 16 * 1024 ||
        uris.some(uri => uri.length > 2048 || uri.includes("*") || uri.includes("\\") || uri.includes("#"))) return false;
    return uris.every(uri => {
      try {
        const url = new URL(uri);
        if (!url.hostname || url.username || url.password || url.hash) return false;
        return url.protocol === "https:" ||
          (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname));
      } catch { return false; }
    });
  };
  const renderList = (heading, values) => {
    if (!values.length) return;
    const title = document.createElement("h4");
    title.textContent = heading;
    diff.append(title);
    const list = document.createElement("ul");
    list.className = "value-list";
    for (const value of values) {
      const item = document.createElement("li");
      item.textContent = value;
      list.append(item);
    }
    diff.append(list);
  };
  textarea.addEventListener("input", () => {
    reviewed = null;
    confirm.hidden = true;
    password.value = "";
    message.hidden = true;
  });
  reviewButton.addEventListener("click", () => {
    if (!Array.isArray(current) || !clientId || !/^[0-9a-f]{64}$/i.test(revision)) {
      show("Не удалось проверить конфигурацию. Найдите клиента заново.", true);
      return;
    }
    const next = lines();
    if (!valid(next)) {
      show("Укажите уникальные HTTPS-адреса по одному на строку. HTTP допускается только для localhost.", true);
      return;
    }
    if (next.length === current.length && next.every((value, index) => value === current[index])) {
      show("Адреса не изменились. Сохранять нечего.");
      return;
    }
    reviewed = next;
    diff.replaceChildren();
    renderList("Добавятся", next.filter(value => !current.includes(value)));
    renderList("Удалятся", current.filter(value => !next.includes(value)));
    const unchanged = next.filter(value => current.includes(value));
    renderList("Останутся", unchanged);
    confirm.hidden = false;
    message.hidden = true;
    confirm.querySelector("h3").focus();
  });
  cancel.addEventListener("click", () => {
    reviewed = null;
    confirm.hidden = true;
    password.value = "";
    reviewButton.focus();
  });
  save.addEventListener("click", async () => {
    if (!reviewed || !password.value) {
      show("Сначала проверьте изменения и введите ваш текущий пароль.", true);
      return;
    }
    save.disabled = true;
    const next = reviewed;
    const secret = password.value;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/admin/clients/redirects", {
        method: "POST", credentials: "include", cache: "no-store", signal: controller.signal,
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie(), Accept: "application/json" },
        body: JSON.stringify({ client_id: clientId, expected_revision: revision,
          redirect_uris: next, current_password: secret }),
      });
      password.value = "";
      if (response.status === 200) {
        const updated = await response.json();
        const check = await fetch("/api/v1/auth/admin/clients/search", {
          method: "POST", credentials: "include", cache: "no-store",
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          body: JSON.stringify({ client_id: clientId }),
        });
        const actual = check.ok ? (await check.json()).client : null;
        if (actual?.redirect_revision === updated.redirect_revision &&
            JSON.stringify(actual.redirect_uris) === JSON.stringify(next)) {
          current = next;
          revision = updated.redirect_revision;
          const addressList = document.querySelector("#client-result .value-list");
          if (addressList) {
            addressList.replaceChildren(...next.map(value => {
              const item = document.createElement("li");
              const code = document.createElement("code");
              code.textContent = value;
              item.append(code);
              return item;
            }));
          }
          reviewed = null;
          confirm.hidden = true;
          show("Адреса обновлены и повторно проверены. Проверьте вход во внешний сервис.");
        } else {
          reviewButton.disabled = true;
          show("Запрос принят, но итоговое состояние не подтверждено. Найдите клиента заново перед повтором.", true);
        }
      } else if (response.status === 400) {
        const code = (await response.json()).code;
        show(code === "INVALID_PASSWORD"
          ? "Не удалось подтвердить пароль оператора. Проверьте его и повторите попытку."
          : "Проверьте адреса возврата. Изменения не подтверждены.", true);
      } else if (response.status === 401 || response.status === 403) {
        reviewButton.disabled = true;
        show("Сессия или права оператора изменились. Войдите снова и найдите клиента заново.", true);
      } else if (response.status === 409 || response.status === 404) {
        reviewButton.disabled = true;
        show("Конфигурация клиента изменилась. Найдите клиента заново и сравните адреса.", true);
      } else {
        reviewButton.disabled = true;
        show("Результат неизвестен. Не повторяйте изменение вслепую: сначала найдите клиента заново.", true);
      }
    } catch {
      password.value = "";
      reviewButton.disabled = true;
      show("Связь прервалась. Результат неизвестен; сначала найдите клиента заново.", true);
    } finally {
      clearTimeout(timer);
      save.disabled = false;
    }
  });
})();
