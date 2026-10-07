(() => {
  "use strict";
  const button = document.getElementById("export-cancel");
  const status = document.getElementById("export-status");
  const error = document.getElementById("export-error");
  if (!button || !status || !error) return;

  const id = new URLSearchParams(location.search).get("id") || "";
  const token = location.hash.slice(1);
  history.replaceState(null, "", location.pathname + location.search);
  if (!/^[0-9a-f]{32}$/u.test(id) || !/^[A-Za-z0-9_-]{43}$/u.test(token)) {
    button.disabled = true;
    error.textContent = "Ссылка неполная. Откройте её заново из письма.";
    error.hidden = false;
    return;
  }

  let busy = false;
  button.addEventListener("click", async () => {
    if (busy) return;
    busy = true;
    button.disabled = true;
    error.hidden = true;
    status.textContent = "Отменяем запрос…";
    status.hidden = false;
    try {
      const response = await fetch(`/api/v1/auth/data/exports/${id}/cancel`, {
        method: "POST", credentials: "omit", cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (!response.ok) {
        throw new Error(response.status === 404
          ? "Запрос уже отменён, истёк или ссылка недействительна."
          : "Не удалось подтвердить отмену. Повторите попытку позже.");
      }
      const result = await response.json();
      status.textContent = result.cleanup_pending
        ? "Выдача архива остановлена. Удаление уже созданного файла завершается."
        : "Запрос отменён. Ссылка на архив больше не действует.";
    } catch (failure) {
      error.textContent = failure instanceof Error ? failure.message : "Не удалось отменить запрос.";
      error.hidden = false;
      status.hidden = true;
      busy = false;
      button.disabled = false;
    }
  });
})();
