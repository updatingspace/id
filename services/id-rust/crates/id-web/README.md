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
The opt-in `/admin/` area offers read-only deletion-request and account lookups
by exact ID or verified primary email. It verifies the operator session through `id-api` before
rendering and does not query YDB. Its templates and stylesheet are
frontend-owned; the API owns authorization and account/request state. Account
lookup shows effective ID access status (including a pending deletion, disabled
account, inactive identity, or broken binding) and identity binding, not
credentials or editing controls. The label is a snapshot, not a command to
change access.
Email lookup submits a read-only POST from the SSR form to `id-web`, then to
`id-api`; the address is not placed in a page or API URL. Both responses use
`Cache-Control: no-store`.
The separately gated suspension review checks the exact account, shows the
effect on access, and requires a fixed reason plus the operator's current
password. Browser JavaScript sends the confirmation to `id-api` with CSRF and
re-reads the account before claiming success. Unknown outcomes are shown as
uncertain. The production operator area and this action remain disabled until
an operator rehearsal. Other operator tasks are not yet available in this UI.

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
