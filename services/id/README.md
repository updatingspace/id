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

The runtime image contains the locked Python environment, application code, and
native shared libraries. Compilers, development headers, and `uv` stay in the
build stage. Python bytecode is compiled during the build, and files are copied
with their final ownership so a recursive `chown` does not duplicate the Python
environment in another layer. The worker count and application startup hooks
are unchanged.

Inside the runtime container, run management commands with `python`, for example
`python src/manage.py check`. Source-based development and CI runners continue
to use `uv run --frozen`; `uv` is intentionally absent from the runtime image.

From the repository root, verify the built image without network access or cloud
credentials:

```bash
docker run --rm --network none --cpus=1 --memory=1g \
  --mount "type=bind,src=${PWD}/scripts/ci/smoke_backend_image.py,dst=/tmp/smoke_backend_image.py,readonly" \
  --entrypoint python updspaceid /tmp/smoke_backend_image.py
```

PR image validation runs this check for native crypto/image/database libraries,
Yandex CA trust, non-root execution, fork-safe telemetry, the background-job
entrypoint, and public API responses. Reducing image size and compilation work
can reduce cold-start overhead; it does not guarantee a sub-500 ms first request
when Serverless Containers scales to zero.

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

## Avatar refresh job

Profile reads and signup no longer download Gravatar images or check object
existence in S3. They return stored avatar metadata immediately. Gravatar
refresh is an explicit batch job using the same database/media environment:

```bash
uv run --frozen python src/manage.py refresh_gravatars --limit 100
```

The production Terraform profile enables a private job container and an hourly
timer. It uses `app.jobs:application`, batches of 25 profiles, and two retries
on failure. The scheduler is the only principal granted invocation rights;
the job has no route in the public API Gateway. The batch respects opt-outs and
uploaded avatars and selects profiles due for the existing seven-day refresh
interval. Network/storage failures are reported and remain eligible for retry.
Do not run it as an in-process background thread in the HTTP serverless container.

The image trusts the official Yandex Cloud CA from
`https://storage.yandexcloud.net/cloud-certs/CA.pem` for the private managed
cache's TLS connection. The bundled CA expires on 2027-06-20 and must be renewed
before then. Redis credentials are injected from Lockbox.

Authentication and OAuth responses, including errors, are marked
`Cache-Control: private, no-store` independently of frontend asset caching.

## Account email and recovery

Password recovery, email verification, and security notifications use the configured
SMTP backend. For iCloud and `account@updspace.com`, see
[delivery setup and verification](docs/email-delivery.md).
