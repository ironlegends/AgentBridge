# Contributing to Agent Bridge

Thank you for your interest in contributing to **Agent Bridge**!

## Development Setup

### Prerequisites
- Current stable Rust toolchain, matching the CI configuration (Edition 2021)
- Git
- Python 3 for the release, packaging and repository-hygiene scripts and their tests in `scripts/rust`
- Node.js for the dependency-free desktop frontend state tests (`node --test`); it is a development tool only, never a runtime dependency
- Google Chrome at a qualified standard installation for native browser tests; Unix CI requires those tests to run.
- Linux native window tests: Xvfb, XKB utilities and base fonts (the fixture uses a disposable display).

### Build & Test

Run the full workspace regression suite across all 14 crates:

```sh
cargo test --locked --workspace
```

Run the independent native desktop application tests (separate Cargo workspace) and its frontend state tests:

```sh
cargo test --locked --manifest-path app/src-tauri/Cargo.toml
node --test app/tests/live-profile.test.cjs
```

Run the Python script tests from `scripts/rust`:

```sh
cd scripts/rust
python3 -m unittest discover -p "test_*.py"
```

Some script tests are skipped on Windows when they need Unix symlinks or platform tools.

Build the standalone release binary:

```sh
cargo build --locked --release -p agent-bridge
```

## Non-Negotiable Architecture & Security Rules

Before opening a pull request, please verify your changes preserve these core invariants:

1. **Zero extra runtimes:** Do not introduce Node.js, Python, Playwright, or external runtime dependencies into the `agent-bridge` runtime path.
2. **Fail-closed by default:** New capabilities must be opt-in on the local CLI or private operator settings - never widen permissions from MCP requests.
3. **Minimal dependencies:** Keep `Cargo.lock` lean and deterministic; justify any new crate dependency clearly in your PR description.
4. **Cross-platform code:** Keep `cargo test --locked --workspace` compiling and passing on Windows, Linux, and macOS. Pull requests run the fast Ubuntu lane (hygiene, script tests, workspace compilation and the portable crates). The full Windows, Linux and macOS matrix runs separately as an explicit qualification run, so test locally on the platforms your change touches. Gate OS-specific FFI cleanly behind `#[cfg(windows)]` / `#[cfg(unix)]` / `#[cfg(target_os = ...)]`.
5. **No secrets or personal paths:** Never commit tokens, private keys, personal usernames, local machine names, or debug symbols (`*.pdb`).
6. **English documentation and prompts:** Keep code comments, CLI output, confirmation prompts, and docs in clear English.

## Comment policy

Keep comments that explain an invariant, ownership or lifetime, a platform constraint, an external protocol, or a non-obvious decision. Keep public API documentation and license notices. Remove obsolete explanations and narration that only repeats the adjacent code after checking the entire surrounding function.

The Rust comment ratchet checks new deferred-work markers and decorative separators. It lexes Rust strings, raw strings, character literals, nested block comments and documentation comments before classifying comment text. It does not rewrite files or decide whether a safety explanation is useful.

```sh
python3 -m unittest discover -s scripts/rust -p test_comment_ratchet.py
python3 scripts/rust/comment_ratchet.py
python3 scripts/rust/comment_ratchet.py --base-ref origin/main
```

CI compares with the complete pull request's base Git tree, or the previous main commit for pushes, so editing the local baseline or adding a later clean commit cannot grant new allowances. Removing an existing finding cannot pay for a new comment with different text or in another file. The optional `/delete-comment` skill follows this policy; comment removal must preserve behavior, tool directives, license terms and safety reasoning.

The current inventory, scope and retained-comment decisions are documented in [docs/COMMENT-AUDIT.md](docs/COMMENT-AUDIT.md).

## Pull Request Process

1. Create a topic branch from `main` (e.g., `feat/short-name` or `fix/short-name`).
2. Add or update native Rust regression tests in the affected crate's `tests/` directory covering both the happy path and fail-closed error cases.
3. Update `README.md` or `docs/` if CLI flags, MCP tools, or security boundaries change.
4. Run `cargo test --locked --workspace`, plus the desktop and script tests above when your change touches `app/` or `scripts/`, and confirm all tests pass.
5. Open a pull request against `main` using the PR template.

## License

By contributing, you agree that your contributions will be licensed under the **Apache License, Version 2.0** (see [LICENSE](LICENSE)).
