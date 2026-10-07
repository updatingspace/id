(() => {
  "use strict";
  const storedTheme = () => {
    try { return localStorage.getItem("id-theme") || "system"; } catch { return "system"; }
  };
  const applyTheme = (value) => {
    document.documentElement.dataset.theme = ["light", "dark"].includes(value) ? value : "system";
  };
  applyTheme(storedTheme());
  addEventListener("storage", event => { if (event.key === "id-theme") applyTheme(storedTheme()); });
  document.addEventListener("DOMContentLoaded", () => {
    if (document.body.hasAttribute("data-public-home")) {
      fetch("/api/v1/auth/me", { credentials: "include", cache: "no-store", signal: AbortSignal.timeout(8000) })
        .then(response => response.ok ? response.json() : null)
        .then(body => {
          if (!body?.user) return;
          for (const link of document.querySelectorAll('a[href="/login"]')) {
            link.href = "/account";
            link.textContent = "Продолжить в аккаунте";
          }
          for (const link of document.querySelectorAll('a[href="/signup"]')) {
            link.href = "/login";
            link.textContent = "Другой аккаунт";
          }
          const headerLogin = document.querySelector('.site-header a[href="/account"]:not(.header-account):not(.brand)');
          if (headerLogin) headerLogin.hidden = true;
          const lead = document.querySelector(".lead");
          lead.textContent = `Вы вошли как ${body.user.email || body.user.username}. Управляйте профилем, защитой и доступом приложений.`;
        }).catch(() => {});
    }
    for (const select of document.querySelectorAll("[data-theme-select]")) {
      select.value = document.documentElement.dataset.theme;
      select.addEventListener("change", () => {
        applyTheme(select.value);
        for (const other of document.querySelectorAll("[data-theme-select]")) other.value = select.value;
        try { localStorage.setItem("id-theme", select.value); } catch {}
      });
    }
    for (const time of document.querySelectorAll("time[datetime]")) {
      const date = new Date(time.dateTime);
      if (!Number.isNaN(date.valueOf())) {
        time.textContent = new Intl.DateTimeFormat("ru", { dateStyle: "medium", timeStyle: "short" }).format(date);
        time.title = `${time.dateTime} · время этого устройства`;
      }
    }
    for (const list of document.querySelectorAll("#totp-recovery-codes, #passkey-recovery-codes, #recovery-rotation-codes")) {
      const actions = document.createElement("div");
      actions.className = "actions";
      const notice = document.createElement("p");
      notice.setAttribute("role", "status");
      notice.hidden = true;
      const codes = () => [...list.querySelectorAll("li")].map(item => item.textContent).join("\n");
      const copy = document.createElement("button");
      copy.type = "button";
      copy.textContent = "Скопировать коды";
      copy.addEventListener("click", async () => {
        if (!codes()) return;
        try {
          await navigator.clipboard.writeText(codes());
          notice.textContent = "Коды скопированы. Сохраните их в надёжном месте.";
        } catch {
          notice.textContent = "Копирование недоступно. Выделите коды вручную или скачайте файл.";
          list.tabIndex = -1;
          list.focus();
        }
        notice.hidden = false;
      });
      const download = document.createElement("button");
      download.type = "button";
      download.textContent = "Скачать коды (.txt)";
      download.addEventListener("click", () => {
        if (!codes()) return;
        const url = URL.createObjectURL(new Blob(["UpdSpace ID — резервные коды\nХраните отдельно от устройства для входа. Каждый код используется один раз.\n\n" + codes()], { type: "text/plain;charset=utf-8" }));
        const link = document.createElement("a");
        link.href = url;
        link.download = "updspace-recovery-codes.txt";
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        notice.textContent = "Файл передан браузеру. Убедитесь, что он сохранён, прежде чем продолжить.";
        notice.hidden = false;
      });
      actions.append(copy, download);
      list.after(actions, notice);
    }
    for (const input of document.querySelectorAll("input[type=password]")) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "password-toggle";
      button.textContent = "Показать";
      button.setAttribute("aria-label", "Показать пароль");
      button.setAttribute("aria-controls", input.id);
      button.setAttribute("aria-pressed", "false");
      button.addEventListener("click", () => {
        const shown = input.type === "password";
        input.type = shown ? "text" : "password";
        button.textContent = shown ? "Скрыть" : "Показать";
        button.setAttribute("aria-label", shown ? "Скрыть пароль" : "Показать пароль");
        button.setAttribute("aria-pressed", String(shown));
      });
      const field = document.createElement("div");
      field.className = "password-field";
      input.before(field);
      field.append(input, button);
    }
    document.addEventListener("invalid", event => {
      const input = event.target;
      for (let panel = input.closest("details"); panel; panel = panel.parentElement?.closest("details")) panel.open = true;
      input.setAttribute("aria-invalid", "true");
    }, true);
    document.addEventListener("input", event => event.target.removeAttribute("aria-invalid"));
    for (const alert of document.querySelectorAll('[role="alert"]')) {
      alert.tabIndex = -1;
      new MutationObserver(() => {
        if (!alert.hidden && alert.textContent.trim()) {
          for (let panel = alert.closest("details"); panel; panel = panel.parentElement?.closest("details")) panel.open = true;
          alert.focus({ preventScroll: false });
        }
      }).observe(alert, { childList: true, attributes: true, attributeFilter: ["hidden"] });
    }
  });
})();
