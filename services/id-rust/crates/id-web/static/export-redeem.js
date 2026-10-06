(() => {
  "use strict";
  const button = document.getElementById("export-download");
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
    status.textContent = "Проверяем ссылку…";
    status.hidden = false;
    try {
      const response = await fetch(`/api/v1/auth/data/exports/${id}/redeem`, {
        method: "POST", credentials: "omit", cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (!response.ok) {
        throw new Error(response.status === 404
          ? "Ссылка ещё не готова, недействительна или срок доступа истёк."
          : "Не удалось проверить ссылку. Повторите попытку позже.");
      }
      const result = await response.json();
      const url = new URL(result.download_url);
      if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) {
        throw new Error("Некорректный адрес архива.");
      }
      status.textContent = "Открываем приватный архив…";
      window.location.assign(url.href);
    } catch (failure) {
      error.textContent = failure instanceof Error ? failure.message : "Не удалось получить архив.";
      error.hidden = false;
      status.hidden = true;
      busy = false;
      button.disabled = false;
    }
  });
})();
