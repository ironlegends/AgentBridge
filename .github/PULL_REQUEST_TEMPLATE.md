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
- [ ] Added or updated regression tests (happy path + fail-closed cases)
- [ ] Updated `README.md` / `docs/` if CLI flags, tools, or security invariants changed
- [ ] Confirmed zero secrets, personal paths, or debug artifacts (`*.pdb`) are included
