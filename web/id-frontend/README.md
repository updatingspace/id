# UpdSpace ID Frontend

Standalone SPA for the ID service.

## Setup
```
npm install
npm run dev
```

## Env
Create `.env` from `.env.example`:
```
VITE_ID_API_BASE_URL=http://id.localhost/api/v1
VITE_ID_OIDC_BASE_URL=http://id.localhost/oauth
```

## Routes
- `/login` – вход
- `/signup` – регистрация
- `/authorize` – consent screen (OAuth/OIDC)
- `/account` – настройки аккаунта
