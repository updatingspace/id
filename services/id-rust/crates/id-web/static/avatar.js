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
  let busy = false;
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
        window.location.replace("/login?next=%2Faccount");
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
    } else {
      image.removeAttribute("src");
      image.hidden = true;
      placeholder.hidden = false;
      remove.disabled = true;
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
    busy = true; submit.disabled = true; remove.disabled = true;
    message.hidden = true; error.hidden = true;
    try {
      const body = new FormData();
      body.append("avatar", selected);
      const result = await send("POST", body);
      if (!result) return;
      updatePreview(result.avatar_url);
      form.reset();
      message.textContent = "Аватар обновлён.";
      message.hidden = false;
    } catch (failure) { showError(failure); }
    finally { busy = false; submit.disabled = false; remove.disabled = image.hidden; }
  });

  remove.addEventListener("click", async () => {
    if (busy || remove.disabled) return;
    busy = true; submit.disabled = true; remove.disabled = true;
    message.hidden = true; error.hidden = true;
    try {
      const result = await send("DELETE");
      if (!result) return;
      updatePreview(null);
      message.textContent = "Аватар удалён.";
      message.hidden = false;
    } catch (failure) { showError(failure); }
    finally { busy = false; submit.disabled = false; remove.disabled = image.hidden; }
  });
})();
