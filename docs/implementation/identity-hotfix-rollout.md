# Identity hotfix: two-phase rollout

This runbook describes the additive identity migration and compatible runtime
rollout introduced after `92c7dbc` (main #127).

## Contract and scope

`AccountIdentity` freezes the public OIDC `sub` once. It is an opaque string,
which can be a historical auth-user number or historical master UUID. Never
parse it as a UUID and never derive a UUID from it. The separate `user_id` claim
is the canonical linked UpdSpace master UUID. When no verified master is linked,
`user_id` is absent. Internal clients must handle that absence explicitly, without
falling back to `UUID(sub)` or inventing an identity.

Verified primary-email ownership permits one initial, unambiguous legacy link.
The frozen subject reproduces the old exact lookup on normalized email; a uniquely
owned case-variant master can be attached without changing an old numeric subject.
Existing bindings never follow later email changes. A late email-matched master,
ambiguous ownership, or unverified attempt to claim an existing master fails
closed. Existing banned/suspended identities cannot log in or obtain OIDC tokens.
Unverified accounts do not gain masters. Provisioning creates no tenant membership;
the existing explicit tenant-header bridge requires the shared-secret internal HMAC
signature before it can create any tenant or membership. Missing, invalid or expired
signatures are ignored as tenant context, while standalone login still succeeds.
Existing membership status and role are preserved. The current HMAC protocol does
not include tenant headers in its signed payload: authenticating the caller is a
necessary boundary, not a complete tenant-authorization policy. That protocol is
unchanged in this hotfix.

New tokens snapshot their frozen subject. Legacy signed access tokens continue only
when their signed subject matches the immutable binding. Legacy opaque refresh
tokens have no verifiable subject history and require fresh authorization. This is
a deliberate one-time compatibility boundary, not a reauthorization on every login.

This patch excludes UI, mail/email-change flows, signing-key changes, tenant role
ownership reconciliation, recovery changes and the broader OAuth protocol/SSO/CAS
refactor. Those remain in the full integration package. No new paid service or
background worker is introduced. Bound identity resolution does not reprovision or
query primary-email ownership again; the SQLite regression asserts no repeat writes.

## Phase 1: expand schema and freeze subjects

1. Verify a backup/recovery point and inspect migration dry-run output using the
   exact candidate artifact. Keep `ID_GLOBAL_IDENTITY_PROVISIONING=false` (default).
2. For SQL, run normal `migrate`. For YDB, run `migrate_ydb --dry-run`, then
   `migrate_ydb`, then `migrate_ydb --check`. The YDB migration ledger verifies
   immutable checksums. Unknown schema/type/nullability drift refuses the rollout.
   New fields are additive and nullable so old binaries can still write old rows.
3. Both SQL data migration and YDB backfill only freeze existing subjects/links;
   they never create master identities, even if provisioning is accidentally enabled
   for the migration process. Ambiguous ownership stops migration for operator review.
   Unverified matches remain unlinked and blocked; no ownership is guessed.
4. Promote the compatible runtime with provisioning disabled. Verify readiness,
   password/passkey login and token issuance. A verified standalone account must
   retain its old numeric/opaque `sub`, have no new master, and have no tenant access.
5. Establish this compatible artifact as the rollback target and allow pre-hotfix
   instances to drain. Keep its image/revision available. Coordinate internal clients
   to consume canonical `user_id` and handle its temporary absence.

Phase 1 alone intentionally does not fix the missing-master Portal dependency.
Its purpose is to make the next phase safe to enable and safe to roll back.

## Phase 2: enable provisioning

**Verified release prerequisite:** the rollback target must already contain immutable
`AccountIdentity` resolution and canonical `user_id` handling. Do not enable this
phase while any pre-hotfix artifact is the rollback target or serving requests.
The authorized release task must verify the serving and rollback artifacts before
enabling the flag. This patch itself does not change cloud configuration or select
a production rollback revision.

1. Enable `ID_GLOBAL_IDENTITY_PROVISIONING=true` for the compatible runtime.
2. On verified password/passkey login or OIDC resolution, an unbound account obtains
   its own new master UUID. Its existing public subject stays exactly unchanged.
3. Verify a previously standalone account: `sub` equals its pre-rollout value,
   `user_id` is a UUID, refresh/UserInfo agree, and no membership was created merely
   by global provisioning. Check existing verified UUID principals separately.
4. Roll back only to the compatible phase-1 artifact. Turning the flag off stops
   future provisioning; it does not erase masters, change links or change subjects.

Rolling back to pre-hotfix code after phase 2 is unsafe: old code re-resolves by
email and can substitute the new UUID for the historical numeric subject. Reverting
DDL or deleting bindings/masters does not constitute a safe rollback procedure.

## Migration continuity

Hotfix YDB `0001_immutable_identity` contains only the nullable token `subject`
column and `freeze_account_identities_v1` backfill. `AccountIdentity` and its
indexes are created by the current-model bootstrap. The full refactor must retain
this exact first migration checksum and add membership `source` as a separate
`0002_membership_source`; editing an applied `0001` is deliberately rejected.

`migrate_ydb --dry-run` and `--check` are read-only. A crash after additive DDL or
before deferred implicit indexes is resumable. The local rehearsal explicitly drops
one implicit session index, checks that readiness of the schema gate fails without
repairing it, then repairs and verifies an unchanged ledger.
