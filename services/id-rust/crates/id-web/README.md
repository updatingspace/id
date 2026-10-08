# ID web UI

`id-web` is the separately deployed Topcoat web service. `id-api` owns
authentication, credentials, sessions and YDB; the web service has no direct
access to them. Public routes share the ID origin through API Gateway.
The page tasks, wording rules and responsive review checklist are recorded in
[`UX.md`](UX.md).

UI authors can edit `templates/` and `static/` without changing Rust handlers.
The public home page is a static template with a responsive stylesheet.
Gateway/CDN may cache `/_id/*` assets for hours. When changing an existing
stylesheet or script, update its versioned URL in every referencing template
and verify the new bytes through the public domain after deployment.
`/login` and `/signup` are ordinary HTML documents compiled into the web image;
their browser behavior and styles live in `static/`. The login template's
`{{PASSKEY_ACTION}}`, `{{RECOVERY_LINK}}` and `{{SIGNUP_LINK}}` placeholders
accept only checked-in static fragments selected by deployment feature flags.
No request data is interpolated into these placeholders.

The dynamic consent and account pages are Askama
templates with typed Rust page models.
Askama escapes API and profile values before inserting them into HTML. Template
authors can change structure and copy without editing the API integration.
Keep existing form IDs, data attributes and field names when changing account
templates: browser scripts use those hooks. Do not use `safe` or string
replacement for API-provided values.

The account SSR handler calls `id-api` with the request cookie and renders its
response; it does not implement identity business rules.
On the security page, profile and security reads overlap, but the profile result
still controls access: a guest or failed profile returns without waiting for the
security read. Privacy reads overlap only after the profile succeeds, preserving
the preferences, timezones, consents error priority. No auth data is cached.
`scripts/check-web-ssr-reads.cjs` checks overlap with a synthetic API barrier,
denial priority, cookies and feature/section gates against the real web binary.

Successful authenticator setup updates the visible status without reloading,
so newly issued recovery codes remain available. The saved-codes action releases
the leave-page warning and reloads the authoritative account state. This also
applies to passkey setup and recovery-code rotation. The Chromium regression
`scripts/check-web-totp-state-browser.cjs` covers failed confirmation, successful
setup, code retention and explicit completion; it uses a synthetic API and does
not replace the Rust/YDB enrollment tests.

The deletion review at `/account?section=delete` is hidden unless
`ID_WEB_DELETION_ENABLED=true` and both export UI flags are also enabled. It
explains immediate loss of access, asynchronous cleanup and how an export
requested first survives deletion. The browser sends the password and MFA code
directly to `id-api`; a lost response is shown as uncertain and is not retried
automatically. Enable this page only after the API, jobs and recovery timer
have passed the coordinated production gate. `scripts/smoke-web-deletion.sh`
checks the review, mobile width and submission behavior against a mock API;
`scripts/smoke-web-deletion-live.sh` drives a real browser through Topcoat and
the Rust API on an explicitly disposable local YDB, then checks the accepted
request and revoked session. The later cleanup and export-after-deletion flow
has a separate YDB integration test.

Recovery and email verification pages are static HTML templates with browser behavior in
`static/recovery.js`; their Rust handlers only select the document and set
security headers. Frontend authors can change their layout and copy without
editing API or router code, while keeping the form IDs used by the script.
The public export download and cancellation pages follow the same split. They
read an operation ID from the query and a bearer token from the URL fragment,
remove the fragment from browser history, and POST the token without cookies to
the API. The immediate notice contains only the cancellation token; the later
delivery email contains a separate download token. Neither token is rendered
into SSR HTML.
The opt-in `/admin/` area offers read-only deletion and export lookups by
request ID, plus account lookup by exact numeric ID or verified primary email.
It also looks up an OIDC client by exact `client_id` and displays its public
configuration without the client secret. The client ID is
submitted in a bounded POST body, not a URL.
It verifies the operator session through `id-api` before
rendering and does not query YDB. Its templates and stylesheet are
frontend-owned; the API owns authorization and account/request state. Account
lookup shows effective ID access status (including a pending deletion, disabled
account, inactive identity, or broken binding) and identity binding, not
credentials or editing controls. The label is a snapshot, not a command to
change access.
Email and client lookups submit read-only POSTs from the SSR form to `id-web`,
then to `id-api`; the search value is not placed in a page or API URL. Responses use
`Cache-Control: no-store`.
Export lookup shows only lifecycle state, archive preparation and delivery
times; it never exposes the recipient, object key or download capability.
The separately gated suspension review checks the exact account, shows the
effect on access, and requires a fixed reason plus the operator's current
password. Browser JavaScript sends the confirmation to `id-api` with CSRF and
re-reads the account before claiming success. Unknown outcomes are shown as
uncertain. The production operator area and this action remain disabled until
an operator rehearsal. A separate `ID_WEB_ADMIN_CLIENT_REDIRECTS_ENABLED` gate
adds an inline redirect URI review, diff and password confirmation. The browser
sends the change directly to `id-api` with CSRF and re-reads the client before
claiming success. An unknown commit result requires a fresh search, never an
automatic retry. Changing redirects does not revoke previously issued tokens.
Other operator tasks are not yet available in this UI.
`scripts/smoke-web-admin-live.sh` exercises account lookup, deletion status and
suspension confirmation in Chromium against actual Topcoat, Rust API and local
YDB. It uses synthetic accounts and checks the final access state in YDB; it
does not replace a production operator rehearsal. The OIDC client projection and
redirect edit are covered by the local-YDB operator HTTP test, Topcoat SSR smoke and the 320/390/1280
px Chromium operator check.

Run from `services/id-rust`:

```sh
cargo test --locked -p id-web
cargo clippy --locked -p id-web --all-targets -- -D warnings
```

The web image is built by `Dockerfile.web`; a frontend change produces a new
`id-web` image and can be deployed independently of `id-api`.

### Cloudflare and Content Security Policy

The shared Topcoat response layer adds a fresh cryptographic script nonce to
each HTML response's existing CSP and sets `Cache-Control: no-store`, including
the home page. Static CSS/JS keep their existing caching. Do not cache nonce
HTML or add `unsafe-inline`/external script sources to silence CSP errors.
[Cloudflare JavaScript Detections](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/javascript-detections/#if-you-have-a-content-security-policy-csp)
reads the nonce from the HTTP CSP header and applies it to injected scripts;
Bot Fight Mode remains enabled.

The `id.updspace.com` hostname must also have a Cloudflare configuration rule
with expression `http.host eq "id.updspace.com"` and `disable_rum=true` so the
automatic analytics beacon is not injected. The rule applied on 2026-10-08 is
`133d93be67b14a78bf2822194749354e` in ruleset
`0668fc67c72048aab0de0c8a9ace904f`, zone `635e4264df1831a6f6cfa4c91361ef0f`.
After a release, verify the public HTML nonce changes between responses and
check browser CSP events: JSD should receive the nonce, and the RUM beacon
should be absent. Ordinary console logs alone may omit CSP violations.

Browser checks use the small, locked Playwright runner in
`services/id-rust/browser-tests`. Install it with `npm ci` there; the Topcoat
smoke scripts resolve this package without installing the old React frontend.
`scripts/check-web-login-state-browser.cjs` exercises actual Topcoat pages with
a synthetic API: return to the requested account section, clearing MFA after
credential edits, cancellation during form-token preparation, and delayed login
responses. Credential fields become read-only while a login POST is in flight
because that request may already have issued a session cookie.

`scripts/check-web-provider-login-browser.cjs` checks GitHub, Discord and Steam
using a synthetic API. Each button requires its own `login_enabled: true` capability.
The shared UI restores cookie-bound MFA, waits for confirmed cancellation, and
does not replay codes after an unknown result. These checks do not establish
real provider authorization, cookie or Gateway acceptance.
Steam uses OpenID 2.0; the UI forwards the backend's exact authorization URL
without constructing or rewriting `state` or `openid.return_to`.

`scripts/check-web-provider-link-browser.cjs` also checks provider removal:
explicit review/cancel, cookie/CSRF, last-login-method and conflict refusals,
fresh authentication with MFA and return to the selected review, and read-only
recovery after an unknown result. Stored links can be removed even when provider
login is disabled. The frontend sends only `{provider}`; backend owner and
remaining-login-method checks are authoritative. Reauthentication never repeats
the removal automatically. These are synthetic browser checks, not production
provider or YDB acceptance.


The user UI shares `static/ui.css` colour/control tokens and `static/ui.js`
(theme, readable dates, password visibility, error focus and explicit recovery
code copy/download). Load both on every public/account document. The system
colour scheme is the default; an explicit choice is stored locally and applied
before paint. `templates/account-shell.html` owns the six-section navigation,
desktop sidebar and native mobile disclosure. Profile editors use native
`details[name=profile-editor]` so only one opens, without discarding form inputs.
Language/timezone use `section=settings` within Profile; existing query links
remain valid. Each preference view uses the existing partial PATCH contract and sends only its
own fields, so a stale tab cannot overwrite changes made in the other section.

`scripts/check-web-ui-browser.cjs` starts real Topcoat with a synthetic API and
checks 17 pages at 320/390/1280 px in both themes, 200% text (also expanded
forms), token contrast, navigation, draft/error retention, revoked/empty device
lists, consent defaults, theme persistence and current-session vs reauth entry.
Run with the same browser dependencies as the other scripts. `--preview` keeps
the synthetic preview running for manual visual review; it is never a live
account or proof of delivery/deletion success.
