(() => {
  "use strict";

  const form = document.getElementById("profile-form");
  const message = document.getElementById("profile-message");
  const error = document.getElementById("profile-error");
  if (!form || !message || !error) return;

  const button = form.querySelector('button[type="submit"]');
  let busy = false;
  function csrfCookie() {
    const entry = document.cookie.split("; ").find((item) => item.startsWith("csrftoken="));
    if (!entry) return "";
    try { return decodeURIComponent(entry.slice("csrftoken=".length)); }
    catch { return ""; }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    const data = new FormData(form);
    form.setAttribute('aria-busy', 'true');
    for (const input of form.querySelectorAll('input')) input.readOnly = true;
    button.disabled = true;
    error.hidden = true;
    message.hidden = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch("/api/v1/auth/profile", {
        method: "PATCH",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfCookie() },
        body: JSON.stringify(Object.fromEntries(data.entries())),
        signal: controller.signal,
      });
      if (response.status === 401) {
        window.location.replace("/login?next=%2Faccount%3Fsection%3Dprofile");
        return;
      }
      const result = await response.json();
      if (!response.ok || result.ok !== true) {
        throw new Error(typeof result.message === "string" ? result.message : "Не удалось сохранить профиль.");
      }
      const heading = document.getElementById('profile-display-name');
      const name = [data.get('first_name'), data.get('last_name')].map(value => value.trim()).filter(Boolean).join(' ') || heading?.dataset.username || 'Имя не указано';
      if (heading) heading.textContent = name;
      const nameValue = document.getElementById('profile-name-value');
      if (nameValue) nameValue.textContent = name;
      const phone = document.getElementById('profile-phone-value');
      if (phone) phone.textContent = data.get('phone_number').trim() || 'Не указан';
      const birth = document.getElementById('profile-birth-value');
      if (birth) birth.textContent = data.get('birth_date')
        ? new Intl.DateTimeFormat('ru', { dateStyle: 'long' }).format(new Date(`${data.get('birth_date')}T12:00:00`))
        : 'Не указана';
      message.textContent = "Профиль сохранён.";
      message.hidden = false;
      form.closest('dialog')?.close();
    } catch (failure) {
      error.textContent = failure instanceof Error && failure.name !== "AbortError"
        ? failure.message
        : "Не удалось подтвердить сохранение. Обновите страницу и проверьте данные.";
      error.hidden = false;
    } finally {
      clearTimeout(timer);
      busy = false;
      form.removeAttribute('aria-busy');
      for (const input of form.querySelectorAll('input')) input.readOnly = false;
      button.disabled = false;
    }
  });
})();
