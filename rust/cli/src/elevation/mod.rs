//! Unqualified elevation protocol and private native consent implementation.
// Public admission remains fail-closed until the real elevated relay is qualified.
mod protocol;
#[cfg(windows)]
mod broker;
