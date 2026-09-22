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
