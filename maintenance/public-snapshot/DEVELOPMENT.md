# Private development and public snapshots

The private repository is the development authority. The public repository is
a reviewed source snapshot, not a mirror of private history. Never push private
branches or tags to the public repository. The stable release tag is immutable;
a source snapshot does not by itself qualify or publish a new binary release.

## Review and export

Use separate clean checkouts. Fetch both remotes, then record the exact full
private source commit and current public base commit. Do not use moving refs or
copy the private working directory.

Run the following commands from the private checkout (replace placeholders):

    python scripts/rust/export-public-snapshot.py --private-repo <private> --public-repo <public> plan --source <private-commit> --base <public-commit> --output <private-review.json>

Existing public paths form the default allowlist. Private-only paths are excluded
unless individually selected with repeated --include <path> arguments. Removed
public paths are listed as deletions. The plan contains before/after Git blob IDs
and SHA-256 digests; keep it private. Review each changed blob, including binary
assets, configuration, legal notices and any additions/deletions. Check for
secrets, machine/user paths, private project names, credentials, personal data,
private logs, internal links and unsupported claims. A hash or automated scanner
does not replace this review.

After approving the exact plan digest:

    python scripts/rust/export-public-snapshot.py --private-repo <private> --public-repo <public> export --plan <private-review.json> --approved-plan-sha256 <reviewed-sha256> --output <reviewed.patch>

The exporter re-derives the plan from immutable Git objects and produces a
binary-capable patch in a fresh file. It does not fetch, commit, push, copy Git
history, or modify either repository. The patch itself may contain private
material until the review is complete; do not upload it elsewhere.

In the clean public checkout, confirm HEAD is still the recorded public base,
create a review branch and run:

    git apply --check --index <reviewed.patch>
    git apply --index <reviewed.patch>
    git diff --cached --check
    git diff --cached --stat
    python scripts/rust/repository_hygiene.py
    node --test app/tests/live-profile.test.cjs

Compare staged changes to the approved plan and run all applicable release and
CI gates before committing and opening a public PR. For an empty patch no
publication is needed. A stale public base requires a new plan and review.
Keep the private-only export workflow and receipts out of public snapshots.

## Isolated development instance

Use a dedicated development checkout and a separate Windows user or disposable
VM for running an independent native Tauri instance. The production and
development builds currently share the Tauri application identifier and
single-instance behavior; do not assume different command-line configurations
allow two concurrent instances under one Windows user.

Use fresh owner-private database, settings, lifecycle and OAuth directories,
an isolated project and a non-production loopback port. Disable remote tunnel
enrollment for a local-only fixture unless a separately approved development
tunnel and OAuth origin are available. Never copy production OAuth grants or
credentials into development. Build and test against synthetic fixtures before
connecting a development MCP client.

For same-user native testing, first arrange a controlled, reversible handoff:
stop and quit the production owner cooperatively, verify ports and owned child
processes are released, and retain its original task, shortcut, configuration
and state. Restore that owner after testing. Do not force-start a second
instance, delete ownership markers or use an elevated process to evade guards.

The full distribution procedure is in [PUBLIC-RELEASE-SCOPE.md](../../docs/PUBLIC-RELEASE-SCOPE.md)
and [UNIFIED-DESKTOP.md](../../docs/UNIFIED-DESKTOP.md). Test post-reboot behavior only as
the final approved qualification step.
