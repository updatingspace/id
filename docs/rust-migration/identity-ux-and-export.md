# Identity UI and delayed data export

## Product language and navigation

The public home page explains the user's outcomes: one account for UpdSpace
services, visibility into active sign-ins and application access, and control
over account data. Terms such as SSO, PKCE, TOTP and passkeys belong in the
relevant settings or help, not in the first-screen value proposition.

Account navigation is one labelled group. Each page states what it does,
which account is affected, what happens after submission and how to recover
from failure. A cross-service login must say that the user is continuing into
another service; consent must name that service, distinguish required from
optional permissions and leave optional permissions and remembered consent
unselected. Reauthentication must state whether it is a new sign-in, an MFA
confirmation or a fresh proof for a sensitive operation. The admin UI needs a
separate operator task inventory and permission model; an unimplemented admin
route must not be represented as feature parity.

Verify desktop and 390/320 px layouts, keyboard order and visible focus,
screen-reader headings/labels, network failure, back/forward, reload and a
complete login → consent → return flow with a real relying party.

The operator UI is being rebuilt around tasks rather than a dump of internal
models. The first read-only Rust slice checks one deletion request by opaque
number. It shows a human-readable state and the next safe operator step; it
does not expose account identifiers, email or a misleading "delete succeeded"
message before cleanup is confirmed. Access requires an active staff and
superuser session with bound MFA proof. `gateway_rust_admin` is off by default.
This is **not** parity with the old admin: user, client, consent, export, audit,
retry and bootstrap tasks still need dedicated screens or documented `idctl`
procedures. A fresh-authentication requirement for privileged mutations must
be designed before any write action is added to the browser UI.

UI acceptance for each flow is a browser test at 320, 390 and desktop widths,
without horizontal overflow, with keyboard-only operation and visible focus;
the same flow must explain what is being authorised, what happens next, how to
cancel or recover, and what remains pending. A successful HTTP response alone
is not sufficient. For cross-service sign-in, verify that the user sees the
destination, chooses optional data explicitly and returns to the actual
relying party. For export, verify notice, cooldown, cancellation, delivery and
post-deletion redemption as one journey. For the operator screen, verify guest,
non-operator, missing request, pending, running, failed and completed states.

## Export and deletion contract to implement

**Production behavior does not meet this contract.** The deployed export still
uses the immediate, owner-session path. The delayed path below is a local pilot
until the remaining failure and production checks pass.
Read-only YC inspection on 2026-10-07 confirmed that Gateway sends
`/api/v1/auth/data/exports` to Rust container
`bbamj363kmhlj2nof0mo`; its active revision has
`ID_EXPORT_API_ROLLOUT_ENABLED=true` and no delayed-export flag. The active
Topcoat revision has `ID_WEB_EXPORTS_ENABLED=true` but no redeem flag, and the
active jobs revision has neither escrow snapshot nor escrow mail rollout flag.
Changing only one container would create a misleading or broken user journey.
The read-only `scripts/ci/check-yc-delayed-export.mjs` gate also found that
neither active API nor jobs revision binds `ID_EXPORT_ESCROW_KEY`, and jobs has
no public export origin. The private recovery timer is active and targets
Rust jobs, but a timer alone cannot make the workflow available. This gate
prints missing configuration names rather than secret values; it must pass
on the exact tested revisions before an end-to-end production rehearsal.

The Rust workspace now contains additive `id_data_export_escrow` schema,
operation-bound address encryption and deterministic download capability
primitives. The delayed pilot creates the escrow request atomically with the
owner operation and stores a private snapshot under an account-independent
object key. Deletion waits for a pending snapshot and detaches a sealed one.
The local pilot now creates two durable mail intents, sends the request notice
and timed delivery mail through jobs, renders a fragment-only bearer link in
Topcoat, and redeems it without an account session. The existing deletion
profile stage defers while a snapshot is pending and detaches a sealed archive
before deleting the profile. Avatar cleanup also waits for the snapshot. An
accepted escrow export can read an already disabled account while ordinary
new exports remain forbidden. The isolated local-YDB test
`data_export_delete_flow_ydb` now covers public export and deletion HTTP
requests, snapshot upload after access is revoked, owner detachment, the
credential/avatar/profile stages, a clean UUID pass and the Rust finalization
drain. The snapshot is initiated through a real `id-jobs --serve` child and its
private `/internal/jobs/recover-export` HTTP timer route; a queue-shaped event
is rejected and a repeated timer does not create a second snapshot. The event
envelope follows the [Yandex timer message format](https://yandex.cloud/en/docs/serverless-containers/concepts/trigger/timer).
After the
synthetic 24-hour boundary, a second `id-jobs --serve` process uses the same
private route to send the request notice and release mail to a local SMTP
double. It verifies
a `succeeded` deletion receipt, physical removal of the
account, identity and Django session, the cooldown boundary, durable SMTP
delivery and public bearer redemption without a session. The test explicitly
creates its rate-limit cache table rather than relying on a shared database.
CI runs it after the cutover-seal regression in a separate disposable YDB on
port 2137. On 2026-10-06, `idctl data-export-storage-smoke` used the current
production private bucket and S3 credentials to upload synthetic owner-prefix
and escrow-prefix objects, verify both through signed GETs, delete both and
confirm subsequent signed GETs return 404. This proves those storage operations,
not the complete delayed-export flow. The opt-in `ID_EXPORT_TEST_REAL_S3=true`
run of `data_export_delete_flow_ydb` then passed with disposable local YDB,
private production Object Storage and local SMTP: the jobs HTTP timer uploaded
a synthetic archive after access revocation, account finalization removed the
owner, the cooldown was advanced for that synthetic request, mail was sent,
the bearer endpoint returned a signed S3 URL, and the archive was downloaded
and deleted with a subsequent signed GET returning 404. No production account
or production YDB row was used. `yc serverless trigger list` on
2026-10-06 showed the active private five-minute export timer
`updspace-id-rust-export-recovery`, targeting the jobs container's
`/internal/jobs/recover-export` route; Terraform intentionally does not own
this trigger. Successful production invocation through Gateway, production YDB
and SMTP still needs an end-to-end rehearsal. A separate
opt-in expiry sweep deletes
private objects before erasing escrow metadata. Recovery from
ambiguous external outcomes, self-service cancellation, production
key rotation/configuration and browser checks remain. Delayed
export is not enabled in production.

The isolated cutover/finalization regression now confirms that newly written
audit and outbox events for other identities survive deletion finalization and
do not hold it indefinitely. A legacy unbound account still requires empty global
tables; bound identities require a cutover seal and a completed UUID cleanup
pass. The destructive test is restricted to an explicitly disposable YDB on
port 2137. The export-then-delete test now covers the finalization drain;
the production timer's full data flow remains unverified.
Terraform now generates a persistent escrow key into the runtime Lockbox
secret when exports are enabled. Key rotation must retain the old key longer
than every outstanding archive; losing it makes pending delivery impossible.

The local pilot now has a bounded snapshot retry path. After ten expired
claims without a sealed archive, the operation becomes `failed`, the escrow
loses its account binding, and the timed mail reports the failure without a
download link. Expiry cleanup removes the encrypted delivery address even
when no object was created. This prevents an accepted deletion from waiting
forever for an archive that could not be prepared. The exact retry budget and
failure notification timing still need operational tuning under real storage
outages.

An authenticated owner can now revoke a delayed request from its status page;
the Rust API checks the owner and CSRF, cancels both mail intents and revokes
the capability in one YDB transaction, then deletes the private object. A
failed object deletion stays private and is retried by expiry jobs. After
account deletion, the owner session no longer exists, so an unexpected
request can still be revoked by an operator using the opaque request ID shown
in the notification. `idctl data-export-cancel <id>` is read-only;
`idctl data-export-cancel <id> --apply` atomically revokes mail and download
access, then deletes the private object and clears its reference. If Object
Storage deletion fails, the command reports that the link is already revoked
and must be retried; lifecycle and the expiry worker remain fallback cleanup.
An SMTP send already in flight may still deliver a now-useless link. Operator
authentication and request verification are operational controls for this
CLI. A recovery channel for cancellation after account deletion remains open.

Target flow:

1. After password and MFA confirmation, atomically record the request, a
   verified delivery email and `release_at = accepted_at + 24h`. Return an
   operation ID, the exact release time, and a plain-language explanation.
   Send a notification that allows the owner to report an unexpected request.
2. Start **snapshotting immediately**, before unrelated account changes or
   deletion can remove the data. Seal a complete private archive and manifest
   under a random object key. The manifest records what was included and the
   snapshot cutoff; never export password hashes, MFA secrets or bearer tokens.
3. At `release_at`, send an unguessable download capability to the verified
   email. Derive it from a dedicated key without storing the bearer value,
   bind it to this archive and expire it after 24 hours. The capability can be
   redeemed again during that window: a lost HTTP response must not make the
   archive permanently unavailable. Each redemption returns a signed object
   URL valid for at most 60 seconds. The bearer stays in a URL fragment until
   browser JS moves it into a POST body; it must not reach Gateway access logs,
   analytics or a referrer. A live session cannot bypass `release_at`.
4. On account deletion, block sign-in immediately. Final data cleanup waits
   until every earlier accepted export has a sealed archive or a recorded
   terminal failure. Move sealed archives and the encrypted delivery address
   into a short-lived escrow independent of the account row; then the account
   and its credentials can be removed. The release job works from escrow even
   when the account no longer exists. A failed snapshot never becomes a
   success or produces an incomplete download.
5. Delete the archive, encrypted email and operation metadata
   after the delivery window. Retries after an unknown commit must not issue a
   second capability or email with different content. A lost SMTP receipt may
   resend the same notification/capability, never a new export.

Required states: `accepted`, `snapshotting`, `cooldown`, `ready`, `failed`,
`expired`. UI status must distinguish preparation from the 24-hour wait and
show `release_at`, snapshot cutoff and download expiry. A failed export has a
safe retry path. Cancelling an unrecognized request revokes any capability and
does not silently erase an already accepted deletion request.

Acceptance scenarios on real YDB/Object Storage/SMTP test doubles:

- Request → notification → sealed snapshot → 24-hour release → download →
  repeat download inside the window → archive cleanup → further access denied.
- Request → account deletion before snapshot completes → credentials revoked →
  snapshot completes → account removed → release email → download succeeds.
- Request → deletion after snapshot, before release, with the same outcome.
- Snapshot failure, object-upload timeout after commit, notification retry,
  worker crash, lease expiry and 100 concurrent capability uses.
- Changes to profile or email after request do not change the snapshot cutoff
  or delivery recipient; the verified address at request time is disclosed.
- An unrecognized request can be revoked, including after account deletion,
  through a scoped recovery channel or operator procedure.

Do not enable the delayed UI copy or claim deletion-safe exports in production
until these scenarios pass. The existing immediate export remains a known gap.

## Interface acceptance map

### Current implementation audit

The current local home template presents ID as one point of entry and follows
the user's decision at an application sign-in, instead of cataloguing backend
features. Chromium renders the home, operator lookup and export pages without
horizontal overflow at 320, 390 and 1280 px; keyboard and screen-reader checks
remain. The Rust login page renders
entry into another service in the initial HTML, without waiting for browser
JavaScript, and says that confirming the account is not yet consent to share
data.
The app-entry copy distinguishes signing in to ID, completing account MFA
only when configured, and choosing an application's permissions on the next
page. It does not call reuse of a valid session a fresh reauthentication.
Current OIDC supports `prompt=none` and `prompt=consent`, but not
`prompt=login` or `max_age`; forced fresh proof remains a separate backend and
UI task.
The Rust consent page shows the API-validated return origin, presents required
data as fixed information rather than disabled checked controls, leaves
optional data unchecked, and gives denial an equally visible action. Connected
applications now show a review step naming the application before revocation,
with a way to keep access. These copy and layout changes are local code until
deployed and checked through the Gateway.

The account overview now separates task selection from editing personal
details. `/account?section=profile` owns the profile, avatar and email forms;
the overview groups tasks by access, sign-in protection and personal data.
The public home page leads with the single-entry benefit. Local Chromium
layout checks at 320, 390 and 1280 px showed no horizontal overflow for the
home page or the account navigation; these do not replace live Gateway or
assistive-technology checks.
The dead link from profile editing to the removed React cabinet has been
removed. In delayed-export mode the form now names the verified delivery
address, explains notice, 24-hour hold, expiry and post-deletion delivery;
an unverified address shows a confirmation path and no submit control. The
deletion HTTP endpoint is restricted to local debug YDB and its own source
labels it incomplete. Therefore a production deletion control must **not**
be added by merely linking a form to that endpoint. The Rust web has one
read-only operator lookup for deletion requests, gated off in production;
other admin tasks remain open parity gaps. After retiring the React Gateway
fallback on 2026-10-07, production `/admin/` returns an honest 404 rather
than the old React shell. The local layout is not a completed admin console.

The next interface release should use one information architecture across
pages: account overview → devices, applications, sign-in protection, personal
data, privacy, activity. Export and deletion are separate tasks within
personal data. Each subpage has a persistent account breadcrumb/back link,
current account identifier, a single main action, a precise outcome message
and an error recovery path. Mobile layout is one column; controls keep their
labels and reach 44 px. Do not substitute another dashboard of feature names
for this task flow.

The account is a task hub, not an operator dashboard. Its first view should
answer three questions without exposing protocol terms: *Where am I signed
in? Which apps can access my account? What personal data can I manage?* The
header and page navigation stay consistent across the account. On a narrow
screen links become full-width rows, controls remain at least 44 px high, and
no content needs horizontal scrolling at 320 px.

| Journey | Required explanation | Confirmation / escape |
| --- | --- | --- |
| Sign in to ID | Which account and where it leads | Bad credentials leave the user on the form, with the entered email retained |
| Enter an app | Name and verified destination of the app, requested permissions | Deny is as visible as allow; optional permissions and remembering the decision start off |
| Fresh proof for sensitive action | Why password/MFA is requested again; whether an existing session continues | Expired challenge returns to the interrupted task without silently approving it |
| Remove a passkey or session | Which device/key and whether the current session ends | Success says precisely what was revoked; failure makes no success claim |
| Export data | Snapshot begins now, delivery to verified email after 24 hours, expiry and what deletion changes | Owner sees preparation, waiting, ready, failed, expired; unexpected request can be reported |
| Delete account | Access ends immediately; cleanup and any previously requested export continue | Explicit irreversible-action confirmation, no preselected consent or misleading “everything deleted” message |

The operator surface is a separate product area. Before replacing Django
admin, enumerate real tasks (user lookup, account lock, client and redirect
management, pending deletions/exports, audit and retry of failed jobs), map
each to a role and audit record, and run those tasks on a staging dataset. A
plain list of internals or a link to `/legacy/account` is not a replacement.

## Operator surface: screen contract

The current Rust web service has one read-only operator task; it does not yet
replace the operator console. The public account pages must not be labelled
an admin UI.
The replacement belongs in a separate `/admin` area with its own navigation,
authorization and audit trail. The backend supplies typed task endpoints; web
templates decide layout and wording without direct YDB access.

| Screen | Primary task | Required information before action |
| --- | --- | --- |
| Overview | Find an account or an operation needing attention | Search by exact ID or verified email; queue counts with an as-of time, never raw secrets |
| Accounts | Lock/unlock, inspect identity bindings | Current status, reason, affected sessions, operator role and expected effect |
| Applications | Manage OIDC clients and redirects | Exact client and redirect URI diff, environments affected and validation errors |
| Requests | Inspect export/deletion lifecycle; retry safe steps | State, accepted/release/expiry times, step history and whether retry sends mail |
| Audit | Explain who changed what | Actor, timestamp, action, target reference and outcome; sensitive fields redacted |

Every destructive or access-changing action uses a review screen with its
specific target and consequence. The confirmation button says the action
(for example “Заблокировать вход для аккаунта”), while cancellation is equally
visible. Errors leave entered search and review context intact. The UI cannot
turn an unknown backend outcome into a success toast: it re-reads the operation
and reports “состояние уточняется”. A failed job shows whether retry is safe;
there is no generic “повторить всё”. Operators cannot manually shorten an
export cooldown or view an export archive. Screen-reader focus moves to the
result or error heading after a mutation. At 320 px the target, status and
action remain readable without horizontal scrolling.

Acceptance for the first admin release: each task above has a role matrix,
server-side authorization test, audit test and browser path on staging;
non-operators receive 403 even if they know the URL. Account lock and client
redirect edits require a second explicit review step. An export request page
must show a clear distinction among accepted, snapshotting, cooldown, ready,
failed and expired; deletion does not make its prior export disappear from
operator inspection before escrow expiry.
