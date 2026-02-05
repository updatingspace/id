# UpdSpace ID Service

Identity service utilizing Django Allauth and custom auth flows.

## Features
- Headless auth (email + password), JWT session exchange
- MFA (TOTP + recovery codes) and Passkeys (WebAuthn)
- Profile, privacy preferences, consent logging, data export & deletion
- OAuth2/OIDC provider (authorization code + PKCE)

## Run

### Local Dev
```bash
make dev
```

### Docker
```bash
docker build -t updspaceid .
docker run -p 8001:8001 --env-file .env updspaceid
```

## OAuth2/OIDC
OIDC endpoints are exposed outside `/api/v1`:
- `/.well-known/openid-configuration`
- `/oauth/token`
- `/oauth/userinfo`
- `/oauth/jwks`

The authorization UI lives at `/authorize` (handled by the ID frontend), which calls
`/oauth/authorize/prepare` + `/oauth/authorize/approve`.

## ID Frontend
Separate UI app is located at `web/id-frontend`.
Set API endpoints in `.env`:
```
VITE_ID_API_BASE_URL=http://id.localhost/api/v1
VITE_ID_OIDC_BASE_URL=http://id.localhost/oauth
```
