# Form submission latency

The public login, signup, password recovery and email verification forms prepare
their single-use form token when the user first focuses or edits the form.
Opening a page alone does not issue a token or submit user data. If preparation
finishes while the user types, submission can send its POST immediately instead
of first waiting for `GET /api/v1/auth/form_token`.

The preparation is shared only within the current browser document and purpose.
It stays in memory, deduplicates focus/change events and expires conservatively:
request time counts against the server TTL, with five seconds reserved for
submission. Each submission removes its token before awaiting it, so concurrent
attempts cannot reuse the same token. Failed login/MFA attempts require a new
token. The client never automatically replays an authentication POST.

Expired or failed preparations fall back to an ordinary token request at submit
time. Speculative failures have a five-second cooldown to avoid retrying on
every keystroke; explicit submissions can retry immediately. Backend token
validation, rate limits, MFA and email confirmation remain authoritative.

During the 22 September 2026 investigation, a public token request took 1.429 s
end to end from the development environment through Cloudflare. This is one
sample, not a percentile or an end-to-end login benchmark. Preparation removes
that request from the submit-time chain only when it has already completed;
it does not make the backend POST itself faster or eliminate a cold start.

Regression tests cover expiration, purpose isolation, in-flight reuse,
concurrent submissions, failed preparation and MFA retries. Browser tests use
mocked endpoints: no real accounts are created and no emails are sent.

Verification commands, using the pinned pnpm 10.3.0 and Node 22:

```sh
pnpm lint
pnpm typecheck
pnpm test:coverage
pnpm e2e
```

The browser suite builds the production bundle before starting its preview.

## Account consistency and failure handling (2026-09-23)

Account reads propagate HTTP and network errors to the existing bounded React
Query retry flow. A failed read is no longer cached as a successful empty list
or empty preferences. The affected section displays an error with an explicit
retry. Mutation failures remain visible, and action buttons become available
again after a failure.

Successful preference updates immediately replace the account-scoped query
cache using the server response; switching tabs does not resurrect the previous
settings or require a second preferences request. Consent changes refresh both
consents and preferences. TOTP/recovery/passkey mutations refresh MFA status so
subsequent controls and export requirements use the new state. After server-side
account deletion or password change, local authentication is cleared without an
additional logout round trip. Pending profile responses cannot restore it.

The account browser regression suite uses synthetic API responses, including
failures and mutation-dependent state. It verifies UI integration, not live
production authentication or real email delivery.

## Remaining latency target

The requested bound is strictly below 500 ms for complete network requests.
It is **not yet satisfied**. A sequential HTTP/2 series from the diagnostic host
on 2026-09-22 around 21:00 UTC reused one TLS connection across 16 public GETs.
Subsequent health checks took 140–151 ms; providers 160–410 ms; timezones 178–284 ms.
Guest `/auth/me` took 815, 859, 817 and 155 ms, with application durations of
666, 706, 672 and 1 ms. The first health request took 11.5 s (application 1.49 s).
These are individual samples, not representative percentiles or authenticated
account timings. New-connection DNS/TCP/TLS costs must also remain in the report.

A fresh-process local profile of Django's first request identified lazy URL/API
imports: the first health request took 762 ms with profiling enabled, followed
by 3.7 and 2.2 ms guest profile requests. The deployed revision has one prepared
instance, 1 CPU, 1024 MB and concurrency 8. Lazy initialization in four Gunicorn
workers is a next investigation; the public observations alone do not prove
which worker served each request. Authenticated external latency and all account
operations still need a separate live integration check with a test account.
