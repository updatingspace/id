# ID web UI

`id-web` is the separately deployed Topcoat web service. `id-api` owns
authentication, credentials, sessions and YDB; the web service has no direct
access to them. Public routes share the ID origin through API Gateway.

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
response; it does not implement identity business rules. Recovery pages still
use Topcoat `view!` in Rust and need the same frontend ownership treatment.

Run from `services/id-rust`:

```sh
cargo test --locked -p id-web
cargo clippy --locked -p id-web --all-targets -- -D warnings
```

The web image is built by `Dockerfile.web`; a frontend change produces a new
`id-web` image and can be deployed independently of `id-api`.
