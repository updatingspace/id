# Production ID observability audit — 2026-10-08

Read-only YC inventory found exactly five ID containers: API, sessions,
mutations, Topcoat web, and jobs. All active revisions use Rust images with
`BUILD_ID=ddf002374952223ec0b258ca1ab7260d2be73dfc`. No Django or
Gravatar Python ID container appeared in the folder inventory.

All five active revisions have `log_options.folder_id` set to the production
folder rather than `log_options.log_group_id` set to the dedicated
`updspace-id-logs` group (`e23tdfhcg6rl8dg7jpaj`). The dedicated group exists,
but a seven-day read returned only four messages from an older container and
no current login timing. The default group query filtered to the active API
container or revision returned no entries in the checked 24–72 hour windows.
This evidence does not explain an individual slow login or prove that no logs
exist elsewhere; it does show that the intended ID group cannot currently be
used to diagnose the active release.

The local deployment change adds an explicit log-group option to every new
Rust revision and checks it after deployment. Its preflight verifies the group
is readable before changing any revision. The rollback helper still clones the
captured previous revision, including its original logging destination. A
disposable YC CLI-double test covers a source revision with folder logging,
deployment into the ID group, rejection of a mismatched post-deploy group,
and restoration of the prior folder setting.

This change is **not in production**. The active images and logging options
remain those of `ddf0023`. Login latency should be attributed only after a
published deployment establishes log delivery and a real request trace is
measured; a browser's total request duration alone does not identify the
responsible stage.
