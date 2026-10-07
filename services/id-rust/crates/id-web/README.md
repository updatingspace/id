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

The dynamic `consent.html` page and all seven `account-*.html` pages are Askama
templates with typed Rust page models.
Askama escapes API and profile values before inserting them into HTML. Template
authors can change structure and copy without editing the API integration.
Keep existing form IDs, data attributes and field names when changing account
templates: browser scripts use those hooks. Do not use `safe` or string
replacement for API-provided values.

The account SSR handler calls `id-api` with the request cookie and renders its
response; it does not implement identity business rules. Recovery and email
verification pages are static HTML templates with browser behavior in
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

Browser checks use the small, locked Playwright runner in
`services/id-rust/browser-tests`. Install it with `npm ci` there; the Topcoat
smoke scripts resolve this package without installing the old React frontend.
