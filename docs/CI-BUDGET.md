# CI budget policy

Every push to main and every PR revision checks frontend transitions, repository
hygiene, the comment ratchet, Python tests and deterministic source archives.
Draft PRs and documentation or CI-policy-only changes stop there. Ready code
PRs and code changes pushed to main also compile all Rust workspace tests and
run the portable non-CLI crates on Ubuntu. Unknown Git change boundaries select
the quick Rust lane rather than silently treating changes as documentation.
Superseded workflow runs on the same ref and lane are canceled. Automatic CI
never launches the expensive native matrix.

## Full native qualification

After review and a stable candidate, the coordinator deliberately dispatches the
CI workflow with lane full on the exact candidate ref. The default manual input
is quick. Use the full lane sparingly, after economical checks are green:

    gh workflow run ci.yml --ref <candidate-ref> -f lane=full

This runs the existing Windows, Linux and macOS native qualification, standard-user
Windows tests, both Windows Cargo workspaces, real native browser fixture checks,
release builds, archive compilation and CLI smoke checks. The Windows Tauri
workspace is explicitly included in the dependency cache. Hygiene must pass
before expensive runners start; a failing native matrix member cancels redundant
in-progress siblings. If any native member fails or is canceled, the full
qualification gate cannot succeed.

The full qualification record is for the run's exact commit SHA only. A green
economical check, an ignored test, a prior different commit or a skipped native
job is not release qualification. Recheck the exact candidate and full gate before
deployment; physical operator consent, interactive platform tests, signatures,
installer/update/rollback evidence and final reboot gates remain separately
required. Do not rerun the entire matrix to investigate a failing unit test.
Use scoped tests and consolidate changes first. No self-hosted runner is required.

## Baseline (24 November 2026)

Eight recent CI runs consumed about 298 raw runner-minutes, including 258 Windows
minutes. The two documentation-only PR revisions consumed about 80 raw runner-minutes.
Windows Tauri test compilation and release compilation together accounted for
approximately 169 raw minutes across those eight Windows jobs. These are measured
job durations, not the account's billable quota or a measured post-change saving.
Compare new quick and full job durations and cache sizes before changing further.
