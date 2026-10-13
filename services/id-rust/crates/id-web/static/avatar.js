(() => {
  "use strict";

  const form = document.getElementById("avatar-form");
  const file = document.getElementById("avatar-file");
  const image = document.getElementById("avatar-image");
  const placeholder = document.getElementById("avatar-placeholder");
  const remove = document.getElementById("avatar-delete");
  const message = document.getElementById("avatar-message");
  const error = document.getElementById("avatar-error");
  if (!form || !file || !image || !placeholder || !remove || !message || !error) return;

  const submit = form.querySelector('button[type="submit"]');
  const choose = document.getElementById('avatar-choose');
  const fileName = document.getElementById('avatar-file-name');
  let busy = false;
  const selectionChanged = () => {
    if (fileName) fileName.textContent = file.files?.[0]?.name || 'JPEG, PNG или WebP до 6 МБ';
    if (choose) submit.disabled = busy || !file.files?.length;
  };
  choose?.addEventListener('click', () => { if (!busy) file.click(); });
  file.addEventListener('change', () => { error.hidden = true; selectionChanged(); });
  const setBusy = value => {
    busy = value;
    form.setAttribute('aria-busy', String(value));
    submit.disabled = value || Boolean(choose && !file.files?.length);
    remove.disabled = value || image.hidden;
    file.disabled = value;
    if (choose) choose.disabled = value;
  };
  const csrfCookie = () => {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  };
  const showError = (failure) => {
    error.textContent = failure instanceof Error && failure.name !== "AbortError"
      ? failure.message : "Не удалось подтвердить изменение. Обновите страницу и проверьте аватар.";
    error.hidden = false;
  };
  const send = async (method, body) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/avatar", {
        method, body, credentials: "include", cache: "no-store",
        headers: { "X-CSRFToken": csrfCookie() }, signal: controller.signal,
      });
      if (response.status === 401) {
        window.location.replace("/login?next=%2Faccount%3Fsection%3Dprofile");
        return null;
      }
      const result = await response.json();
      if (!response.ok || result.ok !== true) {
        throw new Error(typeof result.message === "string" ? result.message : "Не удалось изменить аватар.");
      }
      return result;
    } finally { clearTimeout(timer); }
  };
  const updatePreview = (url) => {
    if (typeof url === "string" && url.length) {
      image.src = url;
      image.hidden = false;
      placeholder.hidden = true;
      remove.disabled = false;
      remove.hidden = false;
    } else {
      image.removeAttribute("src");
      image.hidden = true;
      placeholder.hidden = false;
      remove.disabled = true;
      remove.hidden = true;
    }
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    const selected = file.files?.[0];
    if (!selected) return;
    if (selected.size > 6 * 1024 * 1024) {
      showError(new Error("Файл слишком большой: максимум 6 МБ."));
      return;
    }
    setBusy(true);
    message.hidden = true; error.hidden = true;
    try {
      const body = new FormData();
      body.append("avatar", selected);
      const result = await send("POST", body);
      if (!result) return;
      updatePreview(result.avatar_url);
      form.reset();
      selectionChanged();
      message.textContent = "Фото профиля обновлено.";
      message.hidden = false;
      form.closest('dialog')?.close();
    } catch (failure) { showError(failure); }
    finally { setBusy(false); }
  });

  remove.addEventListener("click", async () => {
    if (busy || remove.disabled) return;
    setBusy(true);
    message.hidden = true; error.hidden = true;
    try {
      const result = await send("DELETE");
      if (!result) return;
      updatePreview(null);
      message.textContent = "Фото профиля удалено.";
      message.hidden = false;
      form.closest('dialog')?.close();
    } catch (failure) { showError(failure); }
    finally { setBusy(false); }
  });
})();
