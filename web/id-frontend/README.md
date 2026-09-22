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

## Loading and caching

Public routes render without waiting for session restoration. The API uses
`X-Session-Token`; a browser without that token does not call `/auth/me`.
Existing sessions have an eight-second check deadline with a retry screen for
protected routes. A network error preserves the token; a rejected session
clears it. Login/signup use the returned profile, with `/me` as a fallback.

Routes load separate chunks. React Query loads with the account route and its
queries are enabled per section; account navigation does not wait for all data.
Unknown passkey/session counts display a dash until requested. Failed avatar
images fall back to initials.

The publication script uploads dependencies before `index.html`, retains old
assets for active tabs/rollback, and gives fingerprinted assets a one-year
immutable cache policy. See the Yandex Cloud README for deployment details.
