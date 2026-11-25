//! Fixed, pinned Git revision diagnostic under the locally active OS-user mode.
//! The caller holds the live profile read guard and a one-use command permit.
use crate::owned_children::{ChildSpec, OwnedChild};
use crate::runtime::RuntimeError;
use serde_json::{json, Value};
use std::{collections::BTreeMap, ffi::OsString, io, path::Path,
    time::{Duration, Instant}};

const LIMIT: usize = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    truncated: bool,
}
impl Output {
    fn append(&mut self, chunk: &[u8]) {
        let keep = chunk.len().min(LIMIT - self.bytes.len());
        self.bytes.extend_from_slice(&chunk[..keep]);
        self.truncated |= keep < chunk.len();
    }
    fn text(&self) -> String { String::from_utf8_lossy(&self.bytes).into_owned() }
}

// Limit work per poll so a flooding child cannot starve its deadline or stderr.
fn drain(child: &mut OwnedChild, stream: &mut Output, stderr: bool) -> io::Result<bool> {
    let mut buffer = [0u8; 4096];
    for _ in 0..32 {
        let result = if stderr { child.read_stderr(&mut buffer) } else { child.read_stdout(&mut buffer) };
        match result {
            Ok(0) => return Ok(true),
            Ok(n) => stream.append(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

pub(in crate::terminal) fn run_pinned_git_revision(executable: &Path, args: &[String], root: &Path)
    -> Result<Value, RuntimeError>
{
    // Preserve the narrow diagnostic environment rather than exposing the
    // gateway's environment. The OS-user authority is the current token, not
    // inherited credentials, shell expansion or a new arbitrary command.
    // Git for Windows does not interpret a verbatim GIT_DIR as a normal
    // repository path. Reuse the existing identity-checked DOS/UNC conversion.
    let git_root = super::platform::launch_directory(root, false)?;
    let root = git_root.as_path();
    let (git_dir, tree) = agent_bridge_lifecycle::git_revision_windows::repository_directories(root)?;
    let mut env: BTreeMap<OsString, Option<OsString>> = std::env::vars_os()
        .filter(|(name, _)| !name.to_string_lossy().starts_with('='))
        .map(|(name, _)| (name, None)).collect();
    let mut set = |name: &str, value: OsString| {
        env.retain(|key, _| !key.to_string_lossy().eq_ignore_ascii_case(name));
        env.insert(name.into(), Some(value));
    };
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        set("SystemRoot", system_root.clone());
        set("WINDIR", system_root);
    }
    for (key, value) in [
        ("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_CONFIG_GLOBAL", "NUL"),
        ("GIT_TERMINAL_PROMPT", "0"), ("GIT_NO_LAZY_FETCH", "1"),
        ("GIT_NO_OPTIONAL_LOCKS", "1"),
    ] { set(key, value.into()); }
    set("GIT_CEILING_DIRECTORIES", root.parent().unwrap_or(root).as_os_str().to_owned());
    set("GIT_DIR", git_dir.into_os_string());
    if let Some(tree) = tree { set("GIT_WORK_TREE", tree.as_os_str().to_owned()); }

    let spec = ChildSpec {
        executable: executable.to_owned(),
        arguments: args.iter().map(OsString::from).collect(),
        cwd: executable.parent().ok_or("missing Git directory")?.to_owned(),
        env_overrides: env,
    };
    let mut child = OwnedChild::spawn(&spec)?;
    child.close_stdin();
    let deadline = Instant::now() + DEADLINE;
    let (mut out, mut err) = (Output::default(), Output::default());
    let mut stopped = false;
    let mut cleanup_deadline = None;
    let mut timeout = false;
    loop {
        let out_eof = drain(&mut child, &mut out, false)?;
        let err_eof = drain(&mut child, &mut err, true)?;
        if !stopped && (child.try_exit()?.is_some() || Instant::now() >= deadline) {
            timeout = child.try_exit()?.is_none();
            // Root exit ends the owned job, including any descendants.
            child.terminate()?;
            stopped = true;
            cleanup_deadline = Some(Instant::now() + CLEANUP);
        }
        if stopped {
            if let Some(exit) = child.finish()? {
                if out_eof && err_eof {
                    if timeout { return Err("OWNED_DIAGNOSTIC_TIMEOUT: job drained".into()); }
                    let exit_code = exit.code.ok_or("diagnostic exit unavailable")?;
                    return Ok(json!({
                        "exit_code":exit_code,"stdout":out.text(),"stderr":err.text(),
                        "stdout_truncated":out.truncated,"stderr_truncated":err.truncated,
                        "provenance":"current-os-user-owned-git",
                        "git_process_started":true,"owned_job_drained":true
                    }));
                }
            }
            if cleanup_deadline.is_some_and(|limit| Instant::now() >= limit) {
                return Err("OWNED_DIAGNOSTIC_CLEANUP_UNVERIFIED".into());
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
