// Windows-only PE manifest for the agent-bridge CLI.
//
// MSVC's linker embeds this file in the normal executable as RT_MANIFEST #1,
// including the Common Controls v6 side-by-side dependency. It is intentionally
// not copied or patched into any built executable after linking. Other targets
// do not receive Windows linker flags or Windows-only build dependencies.
use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=windows/agent-bridge.manifest");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR")
        .expect("Cargo must provide CARGO_MANIFEST_DIR"));
    let path = root.join("windows").join("agent-bridge.manifest");
    if !path.is_file() {
        panic!("Missing Windows activation manifest: {}", path.display());
    }
    println!("cargo:rustc-link-arg-bin=agent-bridge=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg-bin=agent-bridge=/MANIFESTINPUT:{}", path.display());
}
