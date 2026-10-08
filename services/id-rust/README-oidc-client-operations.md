# OIDC clients: operator CLI

These commands create clients and rotate confidential-client secrets. They do
not change existing redirect allowlists, scopes, issuer, subjects or issued
tokens. They do not enable the public administration routes. The CLI currently
targets Unix operator hosts, matching the deployment tooling.

Use the usual YDB environment and `DJANGO_SECRET_KEY`/fallback keys for the
selected environment. The operator must have an active staff **and** superuser
account, enrolled MFA, and a current ID session carrying verified MFA proof.
The current password is checked before every operation. The committing
transaction checks the session, identity, account, MFA, role and password again.
Database/IAM authorization alone is not an application operator identity.

Supply the operator session and current password in private regular files
(owner access only, typically mode `0600`). The files contain exact bytes:
do not add a trailing newline. Never put these values in command arguments,
shell history, issue bodies or shared logs. The configuration file contains no
credentials; an unexpected field such as `client_secret` is rejected.

## Create

Example `client.json` for a confidential client:

```json
{
  "client_id": "example-rp",
  "name": "Example application",
  "description": "A separately reviewed relying party",
  "redirect_uris": ["https://rp.example.invalid/api/v1/auth/callback"],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"],
  "grant_types": ["authorization_code", "refresh_token"],
  "is_public": false,
  "is_first_party": false
}
```

Client IDs and redirect URIs are exact; no trimming or wildcard matching occurs.
Redirects must be HTTPS, except HTTP loopback development URLs. Fragments,
embedded credentials and duplicate URLs are rejected. Scopes must be supported
by the current ID protocol and include `openid`. Only `authorization_code` and
optional `refresh_token` grants are supported; `offline_access` requires the
latter. The response type is always `code`. Public clients require PKCE through
the existing authorization flow; set `is_public: true` and omit secret output.
Keep `is_first_party` false unless its trust relationship has been reviewed.

```sh
idctl oidc-client-create --config client.json \
  --operator-session-file operator.session \
  --operator-password-file operator.password
```

Without `--apply`, this validates the configuration, verifies the operator and
checks that the client ID is unused. It writes neither YDB rows nor secret files.
Review the JSON report, then apply the same file:

```sh
idctl oidc-client-create --config client.json \
  --operator-session-file operator.session \
  --operator-password-file operator.password \
  --secret-output example-rp.secret.json --apply
```

A confidential client gets a random 256-bit secret, hashed with the same
Argon2id implementation used by the existing client verifier. The raw secret
is written only to a new `0600` file, never stdout, stderr or the audit record.
An existing output path (including a symlink) is rejected. The file and parent
directory are synchronized before attempting the database write, so a lost
commit response does not also lose the candidate credential. The file contains
`client_id`, `client_secret` and the proposed opaque `revision`.

Public clients store an empty secret hash and reject `--secret-output`.
Creation checks absence and inserts the client plus its audit record in one
serializable transaction; duplicate/concurrent creation cannot replace a client.

## Rotate

First obtain and review the existing configuration and its opaque revision:

```sh
idctl oidc-client-rotate-secret --client-id example-rp \
  --operator-session-file operator.session \
  --operator-password-file operator.password
```

Copy the returned revision, then apply with a **new** output filename:

```sh
idctl oidc-client-rotate-secret --client-id example-rp \
  --expected-revision REVIEWED_64_HEX_REVISION \
  --operator-session-file operator.session \
  --operator-password-file operator.password \
  --secret-output example-rp.rotated.secret.json --apply
```

Rotation refuses public clients, ambiguous client IDs and stale reviews. The
revision covers the exact stored client configuration, row ID, previous secret
hash and update time, while exposing none of the secret/hash itself. Only the
secret hash and update time change. Audit attributes the action to the verified
operator identity and contains only client references and opaque revisions.

The old secret stops authenticating after a successful rotation. Authorization
code exchange, refresh and revocation re-read the client authentication inside
their committing transaction; a request authenticated against an obsolete hash
is rejected if rotation wins that transaction ordering. A request committed
before rotation can still return its response afterwards. Already-issued tokens
retain their previous lifecycle; rotation is not token revocation. Coordinate
the relying party's secret update to avoid failed token requests during cutover.

## Failed or uncertain result

Do not assume rollback after a timeout or other unknown commit result. The CLI
only retries YDB's definite `ABORTED` outcome, using the same prepared secret;
it does not blindly retry an unknown commit or generate a second replacement.

Keep any protected secret file created by the command. For a confidential
client, run the rotation command **without** `--apply` to obtain its current
revision and compare it with the file's proposed revision. Equality confirms
that this candidate is currently stored; a different revision means that the
candidate must not be deployed to the relying party. An unavailable review
remains unresolved. A new `--apply` always requires a fresh review and new file.
For uncertain public-client creation, inspect the existing client configuration
through the read-only operator lookup before retrying creation. An existing ID
is never overwritten by the create command.

Remove operator input files when the operation is finished and transfer a
confirmed client secret into the relying party's secret store. This CLI does
not publish secrets to Lockbox or update another service automatically.

## Local verification

The ignored integration test launches real `idctl` processes against local
YDB, uses one isolated synthetic operator, and deletes only its own rows:

```sh
YDB_ENDPOINT=grpc://localhost:2136 YDB_DATABASE=/local \
YDB_CREDENTIALS_MODE=anonymous CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --locked -p id-runtime --test oidc_client_operator_ydb -- --ignored --nocapture
```

The local legacy schema must already exist. This test is not production
acceptance and never authorizes running these mutations against production.
