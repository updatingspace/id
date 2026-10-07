# ID production verification — 2026-10-07

This is a point-in-time observation, not a release sign-off. The unpublished
`codex/rust-id-rollout-current` branch is ahead of the production images.

## Observed deployment

- The active ID API Gateway (`d5d6almt4c5i2ao9e4ha`) has 121 container
  integrations: 47 to the Rust API (`bbak8734de8cabdaorc7`), 60 to Rust
  mutations (`bbamj363kmhlj2nof0mo`), 3 to Rust session reads
  (`bba3ev9oenabp55se69m`), and 11 to Topcoat web
  (`bbai4bjc8f21qg5fvjht`). No Gateway integration names a Python container.
- The active API revision is `bbaltaf4buhpuoontt5p` (2026-10-06) using
  `updatingspace-id-api@sha256:651c280ccad9e0f8ca18772eba57c651d8a6efa2e1c8a51cc419c29c316b7c3f`.
  The active web and jobs revisions are `bbakmjb4ao7ciumkal2p` and
  `bba7gk37q6f4c94d1u0q`.
- The five ID timers listed by Yandex Cloud point to the Rust jobs container
  (`bba9v82d1op2qbh2kqtt`). The container and function listings showed no
  active Django deployment belonging to ID. Portal services were not audited.

## Public, unauthenticated checks

`scripts/ci/smoke-yc-rust-http.mjs` passed all four profiles (`web`, `api`,
`sessions`, `mutations`) against `https://id.updspace.com` on this date:

- Home, login and signup return HTML; the login and signup JS/CSS return
  executable/script and stylesheet MIME types. Retired React assets and
  unknown pages return 404.
- `/health` and `/readyz` return JSON 200. Anonymous `/api/v1/auth/me` returns
  JSON 200. Sessions and export-status access without a session return JSON 401.
- Browser inspection confirmed that `/account` redirects an unauthenticated
  visitor to `/login?next=%2Faccount`, with no console error on the home or
  login page. `/admin/` returns 404 in production.
- A fresh browser read confirmed that the home page explains one account,
  connected services and user-controlled access, and that
  `/login?next=%2Faccount` serves the Topcoat login with password and passkey
  actions. This is a public-page check, not an authenticated journey.
- The strengthened public OIDC smoke passed against the live Gateway:
  discovery has the exact ID issuer and authorize/token/UserInfo/revoke/JWKS
  endpoints, advertises code + PKCE S256 and RS256, and JWKS contains one
  usable signing key. It does not test code exchange or a relying party.

These checks do not prove authenticated journeys, WebAuthn on a physical
authenticator, account deletion, delayed export, operator parity or latency
targets.

## Release gap

The local Passkey registration fix accepts a missing optional `credProps.rk`
response while rejecting explicit `rk=false`, persists the selected
passwordless mode, and has a real local-YDB concurrency/replay regression.
The user reported `INVALID_PASSKEY` from mobile registration. Both live
`/api/v1/auth/passkeys/{begin,complete}` Gateway routes target the API container
above. Its active revision predates the 2026-10-07 `credProps` fix and the old
code rejects absent `rk` with this exact public error. This is a strong cause,
not proof of the iPhone's unobserved credential payload: the sampled production
logs did not expose the rejection category for this attempt.

The local YDB regression passed with an omitted `credProps` result, including
20 concurrent completion attempts and replay rejection. The native Chromium
WebAuthn journey through Topcoat, Rust API and YDB also passed with an omitted
extension result. CI has a mandatory YDB registration step, but the updated
branch has not run on remote CI and the fix is not in the active API revision.
Physical iPhone verification remains required after deployment.

Publishing this branch and deploying the tested image are outstanding.
Production rollout remains incomplete until the authenticated and operator
journeys, delayed export, data checks and performance gates are verified against
their actual production revisions.
