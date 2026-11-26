## Summary

<!-- Explain the problem solved and what changed. -->

## Type of Change

- [ ] Bug fix
- [ ] New feature / platform parity
- [ ] Security hardening
- [ ] Documentation / CI / tooling

## Verification

- [ ] `cargo test --locked --workspace` passes locally
- [ ] `cargo build --locked --release -p agent-bridge` succeeds
- [ ] Native desktop tests pass on Windows (`cargo test --locked --manifest-path app/src-tauri/Cargo.toml`), if affected
- [ ] Desktop frontend tests pass (`node --test app/tests/live-profile.test.cjs`), if affected
- [ ] Python script tests pass (`python3 -m unittest discover -s scripts/rust -p 'test_*.py'`), if affected
- [ ] Repository hygiene passes (`python3 scripts/rust/repository_hygiene.py --repo .`)
- [ ] Rust comment ratchet passes (`python3 scripts/rust/comment_ratchet.py --base-ref origin/main`)
- [ ] Added or updated regression tests (happy path + fail-closed cases)
- [ ] Updated `README.md` / `docs/` if CLI flags, tools, or security invariants changed
- [ ] Confirmed zero secrets, personal paths, or debug artifacts (`*.pdb`) are included
