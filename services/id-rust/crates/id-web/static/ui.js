(() => {
  "use strict";
  const storedTheme = () => {
    try { return localStorage.getItem("id-theme") || "system"; } catch { return "system"; }
  };
  const applyTheme = (value) => {
    const theme = ["light", "dark"].includes(value) ? value : "system";
    document.documentElement.dataset.theme = theme;
    for (const label of document.querySelectorAll('[data-theme-label]')) {
      label.textContent = { system: 'Автоматически', light: 'Светлое', dark: 'Тёмное' }[theme];
    }
    for (const control of document.querySelectorAll("[data-theme-select], [data-theme-choice]")) {
      if (control instanceof HTMLInputElement) control.checked = control.value === theme;
      else control.value = theme;
    }
  };
  const accountPage = document.documentElement.hasAttribute("data-account");
  applyTheme(accountPage ? storedTheme() : "system");
  addEventListener("storage", event => { if (accountPage && event.key === "id-theme") applyTheme(storedTheme()); });
  document.addEventListener("DOMContentLoaded", () => {
    for (const opener of document.querySelectorAll('[data-dialog-open]')) {
      opener.addEventListener('click', () => {
        const dialog = document.getElementById(opener.dataset.dialogOpen);
        if (!(dialog instanceof HTMLDialogElement)) return;
        dialog.showModal();
        if (opener.dataset.dialogFocus) document.getElementById(opener.dataset.dialogFocus)?.focus();
      });
    }
    for (const dialog of document.querySelectorAll('dialog.profile-dialog')) {
      const busy = () => dialog.matches('[aria-busy="true"]') || dialog.querySelector('[aria-busy="true"]');
      for (const close of dialog.querySelectorAll('[data-dialog-close]')) {
        close.addEventListener('click', () => { if (!busy()) dialog.close(); });
      }
      dialog.addEventListener('cancel', event => { if (busy()) event.preventDefault(); });
    }
    applyTheme(accountPage ? storedTheme() : "system");
    for (const control of document.querySelectorAll("[data-theme-select], [data-theme-choice]")) {
      control.addEventListener("change", () => {
        if (control instanceof HTMLInputElement && !control.checked) return;
        applyTheme(control.value);
        try { localStorage.setItem("id-theme", control.value); } catch {}
      });
    }
    for (const time of document.querySelectorAll("time[datetime]")) {
      const dateOnly = time.hasAttribute('data-date-only');
      const date = new Date(dateOnly ? `${time.dateTime}T12:00:00` : time.dateTime);
      if (!Number.isNaN(date.valueOf())) {
        time.textContent = new Intl.DateTimeFormat("ru", dateOnly ? { dateStyle: "long" } : { dateStyle: "medium", timeStyle: "short" }).format(date);
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
