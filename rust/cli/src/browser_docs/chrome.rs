//! Installed-Chrome, one-shot, read-only document rendering.
//! No CDP, webdriver, browser sessions, personal Chrome profile or network URL.
//! A project source file is never given directly to Chrome: only a temporary,
//! fully escaped HTML <pre> with a restrictive CSP is opened using file:///.

#[cfg(windows)]
#[path = "chrome_native.rs"]
mod native;

#[cfg(unix)]
#[path = "chrome_native_unix.rs"]
pub(super) mod native;

#[cfg(any(windows, unix))]
#[path = "chrome_cdp.rs"]
mod cdp;
#[cfg(any(windows, unix))]
pub(super) use cdp::NativeChrome;

#[cfg(all(test, unix))]
#[path = "chrome_test_fixture.rs"]
mod test_fixture;

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Child, Command, Stdio};
#[cfg(windows)]
use std::sync::mpsc;
#[cfg(windows)]
use std::thread;
use std::time::Duration;
#[cfg(windows)]
use std::time::Instant;

#[cfg(windows)]
const CHROME_EXE: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
const CHROME_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_DOM_BYTES: usize = 768 * 1024;
const READ_WAIT: Duration = Duration::from_secs(2);

fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "Installed Chrome/headless DOM transport unavailable")
}
fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Inert Chrome rendering refused")
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Chrome DOM verification failed")
}

/// Operator-only diagnostic. Never print the underlying Error's message,
/// document contents, URL, local paths, network addresses or credentials.
pub(super) fn operator_error(stage: &'static str, error: io::Error) -> io::Error {
    eprintln!(
        "agent-bridge: doc-stage={stage} category={:?} os_code={:?}",
        error.kind(),
        error.raw_os_error()
    );
    error
}
pub(super) fn at_stage<T>(stage: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| operator_error(stage, error))
}

pub(super) fn installed_chrome() -> io::Result<PathBuf> {
    #[cfg(all(test, unix))]
    if let Some(path) = test_fixture::selected()? {
        at_stage("chrome.test_fixture.pin", native::pin_browser(&path))?;
        return Ok(path);
    }
    installed_system_chrome()
}

fn installed_system_chrome() -> io::Result<PathBuf> {
    #[cfg(not(any(windows, unix)))]
    { return Err(unavailable()); }

    #[cfg(unix)]
    {
        // Fixed system installation locations only: no PATH lookup, wrapper
        // script, env override, process discovery or personal profile import.
        #[cfg(target_os = "macos")]
        let candidates = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium"].as_slice();
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let candidates = ["/opt/google/chrome/chrome", "/usr/lib/chromium/chromium",
            "/usr/lib/chromium-browser/chromium-browser"].as_slice();
        #[cfg(not(any(target_os = "macos", all(target_os = "linux", target_env = "gnu"))))]
        let candidates: &[&str] = &[];
        for candidate in candidates {
            let path = Path::new(candidate);
            if fs::symlink_metadata(path).is_ok() {
                at_stage("chrome.installed.unix_pin", native::pin_browser(path))?;
                return Ok(path.to_owned());
            }
        }
        return Err(operator_error("chrome.installed.unix_candidates", unavailable()));
    }
    #[cfg(windows)]
    {
        let path = PathBuf::from(CHROME_EXE);
        let meta = fs::symlink_metadata(&path)
            .map_err(|e| operator_error("chrome.installed.metadata", e))?;
        let physical = fs::canonicalize(&path)
            .map_err(|e| operator_error("chrome.installed.canonical", e))?;
        let physical = physical.to_str().ok_or_else(unavailable)?;
        let dos_path = physical.strip_prefix(r"\\?\").unwrap_or(physical);
        if !meta.is_file() || meta.file_type().is_symlink()
            || !dos_path.eq_ignore_ascii_case(CHROME_EXE)
        {
            return Err(operator_error("chrome.installed.identity", unavailable()));
        }
        Ok(path)
    }
}

#[cfg(windows)]
pub(super) fn random_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    // BCryptGenRandom with system-preferred RNG; no key files or process launch.
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(algorithm: isize, buffer: *mut u8, size: u32, flags: u32) -> i32;
    }
    if unsafe { BCryptGenRandom(0, bytes.as_mut_ptr(), 16, 2) } < 0 {
        return Err(refused());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}
#[cfg(unix)]
pub(super) fn random_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| unavailable())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}
#[cfg(not(any(windows, unix)))]
pub(super) fn random_id() -> io::Result<String> { Err(unavailable()) }

/// Exclusive, randomly named scratch directory in the operator's temp root.
/// Chrome's actual user-data-dir is scratch/profile, never a personal profile.
pub(super) struct PrivateProfile {
    #[cfg(any(windows, unix))]
    native: Option<native::PrivateTree>,
}

impl PrivateProfile {
    pub(super) fn create() -> io::Result<Self> {
        #[cfg(not(any(windows, unix)))]
        { return Err(unavailable()); }

        #[cfg(any(windows, unix))]
        {
            let base = std::env::temp_dir();
            if !base.is_absolute() { return Err(refused()); }
            // Native creation is atomic relative to an already pinned physical
            // directory HANDLE. No directory is opened through a reparse point.
            let native = at_stage("profile.native_create", native::PrivateTree::create(&base))?;
            Ok(Self { native: Some(native) })
        }
    }

    pub(super) fn download_root(&self) -> io::Result<PathBuf> {
        #[cfg(not(any(windows, unix)))]
        { return Err(refused()); }
        #[cfg(any(windows, unix))]
        self.native.as_ref().ok_or_else(refused)?.download_root()
    }

    #[cfg(unix)]
    pub(super) fn read_download(&self, guid: &str, max: usize) -> io::Result<Vec<u8>> {
        self.native.as_ref().ok_or_else(refused)?.read_download(guid, max)
    }

    fn chrome_data(&self) -> io::Result<PathBuf> {
        #[cfg(not(any(windows, unix)))]
        { return Err(refused()); }
        #[cfg(any(windows, unix))]
        self.native.as_ref().ok_or_else(refused)?.data_dir()
    }

    fn new_html(&self, html: &str) -> io::Result<TemporaryHtml> {
        #[cfg(not(any(windows, unix)))]
        { let _ = html; return Err(refused()); }
        #[cfg(any(windows, unix))]
        {
            let (path, pin) = self.native.as_ref().ok_or_else(refused)?.html(html)?;
            Ok(TemporaryHtml {
                path,
                _pin: pin, // cannot rename, replace or edit HTML before Chrome reads it
            })
        }
    }

    /// Preserve scratch when process ownership cannot be confirmed stopped.
    /// Release pins without allowing either this guard or the native Drop to
    /// turn that failure into profile deletion.
    pub(super) fn abandon_cleanup(&mut self) {
        #[cfg(windows)]
        if let Some(tree) = self.native.as_mut() { tree.abandon_cleanup(); }
        #[cfg(any(windows, unix))]
        drop(self.native.take());
    }

    /// Explicit caller contract: Ok(()) means the original temporary profile
    /// and scratch root were deleted by validated HANDLEs and are no longer
    /// reachable at their original paths. Err never certifies cleanup.
    /// Call after the last synchronous render, before reporting 'closed'.
    pub(super) fn cleanup(&mut self) -> io::Result<()> {
        #[cfg(not(any(windows, unix)))]
        { return Err(refused()); }
        #[cfg(any(windows, unix))]
        self.native.as_mut().ok_or_else(refused)?.cleanup()
    }
}
impl Drop for PrivateProfile {
    fn drop(&mut self) {
        // Best-effort fallback only. A successful caller close must explicitly
        // call cleanup() and propagate its result.
        let _ = self.cleanup();
    }
}

struct TemporaryHtml {
    path: PathBuf,
    #[cfg(any(windows, unix))]
    _pin: std::fs::File,
}
// HTML is only removed during the physically pinned, bounded tree cleanup;
// there is no path-only unlink in this guard.

/// Convert our OWN temporary HTML path to an RFC 8089-style file URL.
/// No URL provided by the Web caller ever reaches Chrome.
fn file_url(path: &Path) -> io::Result<String> {
    let raw = path.to_str().ok_or_else(refused)?;
    #[cfg(windows)]
    let data = raw.replace('\\', "/");
    #[cfg(not(windows))]
    let data = raw.to_owned();
    let bytes = data.as_bytes();
    #[cfg(windows)]
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':' || bytes[2] != b'/' {
        return Err(refused());
    }
    #[cfg(not(windows))]
    if !path.is_absolute() { return Err(refused()); }
    let mut out = String::from(if cfg!(windows) { "file:///" } else { "file://" });
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b':' | b'/' | b'.' | b'_' | b'-' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
    Ok(out)
}

fn escape_html(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    for char_ in raw.chars() {
        match char_ {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ => result.push(char_),
        }
    }
    result
}

fn decode_text(raw: &str) -> io::Result<String> {
    // The input is exclusively our escaped HTML rendered back by Chrome.
    // Unknown entities are rejected, not passed through as plausible text.
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(position) = rest.find('&') {
        out.push_str(&rest[..position]);
        let tail = &rest[position..];
        let (replacement, consumed) = if tail.starts_with("&amp;") {
            ('&', 5)
        } else if tail.starts_with("&lt;") {
            ('<', 4)
        } else if tail.starts_with("&gt;") {
            ('>', 4)
        } else if tail.starts_with("&quot;") {
            ('"', 6)
        } else if tail.starts_with("&#39;") {
            ('\'', 5)
        } else if tail.starts_with("&#x27;") {
            ('\'', 6)
        } else {
            return Err(invalid());
        };
        out.push(replacement);
        rest = &tail[consumed..];
    }
    out.push_str(rest);
    Ok(out)
}

pub(super) struct VerifiedRender {
    pub(super) document: String,
}

pub(super) fn render(
    chrome_executable: &Path,
    profile: &PrivateProfile,
    body: &str,
    sha256: &str,
) -> io::Result<VerifiedRender> {
    if chrome_executable != installed_chrome()?.as_path() || sha256.len() != 64
        || !sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || body.len() > 96 * 1024
    {
        return Err(refused());
    }
    at_stage("chrome.installed", installed_chrome())?;
    let marker = at_stage("render.marker", random_id())?;
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let escaped = escape_html(&normalized);
    // A non-newline prefix prevents HTML's special first-newline stripping
    // for <pre>, so byte-for-byte documentary text can be verified.
    let proof_prefix = format!("BRIDGE_DOC_{marker}:");
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta http-equiv=\"Content-Security-Policy\" content=\"sandbox; default-src 'none'; \
         script-src 'none'; connect-src 'none'; img-src 'none'; frame-src 'none'; \
         object-src 'none'; form-action 'none'; base-uri 'none'\">\
         <meta name=\"referrer\" content=\"no-referrer\">\
         <title>Bridge documentary view</title></head>\
         <body><main><pre id=\"bridge-doc-content\" data-proof=\"{marker}\">{proof_prefix}{escaped}</pre>\
         </main></body></html>",
    );
    if html.len() > MAX_DOM_BYTES / 2 {
        return Err(operator_error("render.html_limit", refused()));
    }
    let temp = at_stage("render.html_create", profile.new_html(&html))?;
    let url = at_stage("render.file_url", file_url(&temp.path))?;
    let data = at_stage("render.profile_pin", profile.chrome_data())?;
    // The captured-file experiment provided zero bytes even after natural
    // Job drainage. Restore the bounded stdout pipe, and preserve the
    // original mandatory DOM proof before returning any document text.
    let dom = at_stage("render.chrome_process",
        headless_dom(chrome_executable, &data, &url))?;
    let start_marker = format!("<pre id=\"bridge-doc-content\" data-proof=\"{marker}\">");
    let start = dom.find(&start_marker)
        .ok_or_else(|| operator_error("dom.start_marker", invalid()))? + start_marker.len();
    let end = dom[start..].find("</pre>")
        .ok_or_else(|| operator_error("dom.end_marker", invalid()))? + start;
    let verified_content = dom[start..end].strip_prefix(&proof_prefix)
        .ok_or_else(|| operator_error("dom.content_pin", invalid()))?;
    let rendered = at_stage("dom.decode", decode_text(verified_content))?;
    // Windows Chrome may translate EVERY LF in headless stdout to CRLF.
    // Accept only the exact LF document or the exact full Windows CRLF
    // representation; any other change must still fail identity verification.
    if rendered != normalized
        && !(cfg!(windows) && rendered == normalized.replace('\n', "\r\n"))
    {
        return Err(operator_error("dom.identity", invalid()));
    }
    // Search only the verified canonical LF representation.
    Ok(VerifiedRender { document: normalized })
}

/// Real installed Chrome renders only escaped, inert public documentation.
/// The original HTML and remote URL never reach Chrome; the output's exact
/// title and text must match the locally bounded transcription.
pub(super) fn render_public_inert(
    chrome_executable: &Path,
    title: &str,
    text: &str,
) -> io::Result<VerifiedPublicRender> {
    if chrome_executable != installed_chrome()?.as_path()
        || title.is_empty() || title.len() > 512 || title.chars().any(char::is_control)
        || text.is_empty() || text.len() > 96 * 1024
    {
        return Err(refused());
    }
    let _ = installed_chrome()?;
    let mut profile = PrivateProfile::create()?;
    let observed = (|| {
        let marker = random_id()?;
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        let heading = escape_html(title);
        let content = escape_html(&normalized);
        let prefix = format!("BRIDGE_LEARN_{marker}:");
        let html = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta http-equiv=\"Content-Security-Policy\" content=\"sandbox; \
             default-src 'none'; script-src 'none'; connect-src 'none'; \
             img-src 'none'; style-src 'none'; frame-src 'none'; \
             object-src 'none'; form-action 'none'; base-uri 'none'\">\
             <meta name=\"referrer\" content=\"no-referrer\">\
             <title>{heading}</title></head><body><main>\
             <h1 id=\"bridge-public-title\">{heading}</h1>\
             <pre id=\"bridge-public-text\" data-proof=\"{marker}\">{prefix}{content}</pre>\
             </main></body></html>"
        );
        if html.len() > MAX_DOM_BYTES / 2 { return Err(refused()); }
        let temp = profile.new_html(&html)?;
        let file_url = file_url(&temp.path)?;
        let data_dir = profile.chrome_data()?;
        let dom = headless_dom(chrome_executable, &data_dir, &file_url)?;
        let start_tag = format!("<pre id=\"bridge-public-text\" data-proof=\"{marker}\">");
        let start = dom.find(&start_tag).ok_or_else(invalid)? + start_tag.len();
        let end = start + dom[start..].find("</pre>").ok_or_else(invalid)?;
        let verified = dom[start..end].strip_prefix(&prefix).ok_or_else(invalid)?;
        let rendered = decode_text(verified)?;
        if rendered != normalized
            && !(cfg!(windows) && rendered == normalized.replace('\n', "\r\n"))
        { return Err(invalid()); }
        let ts = dom.find("<title>").ok_or_else(invalid)? + "<title>".len();
        let te = ts + dom[ts..].find("</title>").ok_or_else(invalid)?;
        let actual_title = decode_text(&dom[ts..te])?;
        if actual_title != title { return Err(invalid()); }
        Ok(VerifiedPublicRender { title: actual_title, text: normalized })
    })();
    profile.cleanup()?;
    observed
}

pub(super) struct VerifiedPublicRender {
    pub(super) title: String,
    pub(super) text: String,
}

#[cfg(not(any(windows, unix)))]
fn headless_dom(executable: &Path, data_dir: &Path, url: &str) -> io::Result<String> {
    let _ = (executable, data_dir, url);
    Err(unavailable())
}

#[cfg(unix)]
fn headless_dom(executable: &Path, data_dir: &Path, url: &str) -> io::Result<String> {
    let _binary_pins = native::pin_browser(executable)?;
    cdp::dump_dom(executable, data_dir, url)
}

#[cfg(windows)]
fn headless_dom(
    executable: &Path,
    data_dir: &Path,
    url: &str,
) -> io::Result<String> {
        use std::os::windows::process::CommandExt;
        // Keep the proven process isolation and the existing headless flags;
        // no new console or speculative launch-mode change.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        // Pin Chrome's executable and every ancestor until the child exits.
        // No reparse, replaceable executable, or profile alias is acceptable.
        let _binary_pins = at_stage("chrome.binary_pin", native::pin_browser(executable))?;


        let mut cmd = Command::new(executable);
        cmd.current_dir(data_dir.parent().ok_or_else(refused)?)
            .creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED)
            .arg("--headless=new")
            .arg("--dump-dom")
            .arg("--incognito")
            .arg(format!("--user-data-dir={}", data_dir.display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-background-networking")
            .arg("--disable-component-update")
            .arg("--disable-sync")
            .arg("--disable-extensions")
            .arg("--disable-default-apps")
            .arg("--disable-plugins")
            .arg("--disable-images")
            .arg("--disable-crash-reporter")
            .arg("--disable-breakpad")
            .arg("--no-proxy-server")
            .arg("--disable-features=MediaRouter,OptimizationHints")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_remove("CHROME_USER_DATA_DIR")
            .env_remove("CHROME_LOG_FILE");
        // CREATE_SUSPENDED prevents all Chrome code from running before
        // assignment to the freshly created kill-on-close Job.
        let mut child = cmd.spawn().map_err(|e| operator_error("chrome.spawn", e))?;
        let job = match win::Job::attach(&child) {
            Ok(job) => job,
            Err(e) => {
                let _ = operator_error("chrome.job_attach", e);
                let _ = child.kill();
                let _ = child.wait();
                return Err(unavailable());
            }
        };
        if let Err(e) = win::resume_exact_primary(&child) {
            let _ = operator_error("chrome.thread_resume", e);
            drop(job);
            let _ = child.kill();
            let _ = child.wait();
            return Err(unavailable());
        }
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                let _ = operator_error("chrome.stdout_unavailable", unavailable());
                drop(job);
                let _ = child.kill();
                let _ = child.wait();
                return Err(unavailable());
            }
        };
        let (tx, rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            // Bounded read; no truncation can ever be accepted.
            let _ = tx.send(read_bounded(stdout));
        });
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()
                .map_err(|e| operator_error("chrome.wait", e))? {
                break status;
            }
            if started.elapsed() > CHROME_TIMEOUT {
                let _ = operator_error("chrome.timeout", io::Error::new(io::ErrorKind::TimedOut, "Chrome timed out"));
                drop(job); // Kills root and any Chrome descendants in the Job.
                let _ = child.kill();
                let _ = child.wait();
                return Err(unavailable());
            }
            thread::sleep(Duration::from_millis(30));
        };
        // Preserve the original bounded stdout drain: wait for the pipe
        // within the remaining Chrome deadline, then terminate and drain only
        // this Job. A truncated or failed stream is never accepted.
        let remaining = CHROME_TIMEOUT.saturating_sub(started.elapsed());
        let output = rx.recv_timeout(remaining);
        let finished = job.finish(READ_WAIT);
        drop(job);
        at_stage("chrome.job_finish", finished)?;
        let output = output
            .map_err(|_| operator_error("chrome.stdout_wait", io::Error::new(
                io::ErrorKind::TimedOut, "Bounded Chrome stdout unavailable"
            )))?
            .map_err(|e| operator_error("chrome.stdout_read", e))?;
        if !status.success() {
            return Err(operator_error("chrome.exit_status", unavailable()));
        }
        if output.is_empty() {
            return Err(operator_error("chrome.stdout_empty",
                io::Error::new(io::ErrorKind::UnexpectedEof, "Empty Chrome output")));
        }
        String::from_utf8(output).map_err(|_| operator_error("dom.utf8", invalid()))
}

fn read_bounded(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let len = reader.read(&mut buffer)?;
        if len == 0 { break; }
        if out.len().checked_add(len).is_none_or(|size| size > MAX_DOM_BYTES) {
            return Err(refused());
        }
        out.extend_from_slice(&buffer[..len]);
    }
    Ok(out)
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;

    type Handle = *mut c_void;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimit {
        per_process_user_time: i64,
        per_job_user_time: i64,
        flags: u32,
        minimum_working_set: usize,
        maximum_working_set: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operations: u64,
        write_operations: u64,
        other_operations: u64,
        read_transfer: u64,
        write_transfer: u64,
        other_transfer: u64,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimit {
        basic: BasicLimit,
        io: IoCounters,
        process_memory: usize,
        job_memory: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }

    const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
    const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
    const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION: i32 = 1;

    #[repr(C)]
    #[derive(Default)]
    struct ThreadEntry {
        size: u32,
        use_count: u32,
        thread_id: u32,
        owner_pid: u32,
        base_priority: i32,
        priority_delta: i32,
        flags: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct JobAccounting {
        total_user: i64,
        total_kernel: i64,
        period_user: i64,
        period_kernel: i64,
        faults: u32,
        total: u32,
        active: u32,
        terminated: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(job: Handle, class: i32, data: *const c_void, len: u32) -> i32;
        fn QueryInformationJobObject(
            job: Handle, class: i32, data: *mut c_void, len: u32,
            returned: *mut u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn IsProcessInJob(process: Handle, job: Handle, result: *mut i32) -> i32;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
        fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
        fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry) -> i32;
        fn OpenThread(access: u32, inherit: i32, thread_id: u32) -> isize;
        fn GetProcessIdOfThread(thread: Handle) -> u32;
        fn GetThreadId(thread: Handle) -> u32;
        fn ResumeThread(thread: Handle) -> u32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    struct HandleGuard(Handle);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != (-1isize as Handle) {
                unsafe { CloseHandle(self.0); }
            }
        }
    }

    /// Command was spawned with CREATE_SUSPENDED. Identify exactly one thread
    /// of that exact child, verify its owning PID on the opened thread HANDLE,
    /// and resume it only after the process is proven assigned to our Job.
    pub(super) fn resume_exact_primary(child: &Child) -> io::Result<()> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == (-1isize as Handle) || snapshot.is_null() { return Err(unavailable()); }
        let snapshot = HandleGuard(snapshot);
        let mut entry = ThreadEntry { size: size_of::<ThreadEntry>() as u32, ..Default::default() };
        if unsafe { Thread32First(snapshot.0, &mut entry) } == 0 {
            return Err(unavailable());
        }
        let mut selected = None;
        loop {
            if entry.owner_pid == child.id() {
                if selected.replace(entry.thread_id).is_some() {
                    return Err(unavailable());
                }
            }
            entry.size = size_of::<ThreadEntry>() as u32;
            if unsafe { Thread32Next(snapshot.0, &mut entry) } == 0 { break; }
        }
        let thread_id = selected.ok_or_else(unavailable)?;
        let thread = unsafe {
            OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, 0, thread_id) as Handle
        };
        if thread.is_null() { return Err(unavailable()); }
        let thread = HandleGuard(thread);
        if unsafe { GetProcessIdOfThread(thread.0) } != child.id()
            || unsafe { GetThreadId(thread.0) } != thread_id {
            return Err(unavailable());
        }
        // CREATE_SUSPENDED must have supplied exactly one suspend count.
        if unsafe { ResumeThread(thread.0) } != 1 { return Err(unavailable()); }
        Ok(())
    }

    pub(super) struct Job(Handle);
    // Windows kernel Job HANDLEs are valid across threads. This owned handle
    // is accessed only behind the single NativeProvider mutex; no aliasing or
    // cross-thread GUI state is carried by the pointer itself.
    unsafe impl Send for Job {}

    impl Job {
        pub(super) fn attach(child: &Child) -> io::Result<Self> {
            Self::attach_raw(child.as_raw_handle() as Handle)
        }
        /// Exact process HANDLE from native CreateProcessW with an explicit
        /// inherited-handle whitelist. Called before resuming Chrome's thread.
        pub(super) fn attach_raw(process: Handle) -> io::Result<Self> {
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if handle.is_null() { return Err(unavailable()); }
            let job = Self(handle);
            let mut limits = ExtendedLimit::default();
            limits.basic.flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(job.0, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    (&limits as *const ExtendedLimit).cast(),
                    size_of::<ExtendedLimit>() as u32)
            } == 0 { return Err(unavailable()); }
            if unsafe { AssignProcessToJobObject(job.0, process) } == 0 {
                return Err(unavailable());
            }
            let mut assigned = 0;
            if unsafe {
                IsProcessInJob(process, job.0, &mut assigned)
            } == 0 || assigned == 0 {
                return Err(unavailable());
            }
            Ok(job)
        }
        fn active(&self) -> io::Result<u32> {
            let mut stats = JobAccounting::default();
            if unsafe {
                QueryInformationJobObject(self.0, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                    (&mut stats as *mut JobAccounting).cast(),
                    size_of::<JobAccounting>() as u32, ptr::null_mut())
            } == 0 { return Err(unavailable()); }
            Ok(stats.active)
        }
        /// Emergency cleanup of this exact Job after refusal; the caller
        /// never uses output from a forced termination.
        pub(super) fn finish(&self, timeout: Duration) -> io::Result<()> {
            if self.active()? == 0 { return Ok(()); }
            eprintln!("agent-bridge: doc-stage=chrome.job_force category=JobActive os_code=None");
            if unsafe { TerminateJobObject(self.0, 1) } == 0 {
                return Err(unavailable());
            }
            let started = Instant::now();
            loop {
                if self.active()? == 0 { return Ok(()); }
                if started.elapsed() >= timeout { return Err(unavailable()); }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { CloseHandle(self.0); } }
        }
    }
}


#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    #[test]
    fn private_file_urls_encode_unix_paths_without_reinterpreting_backslashes() {
        assert_eq!(file_url(Path::new("/tmp/bridge selected/é#x\\y.html")).unwrap(),
            "file:///tmp/bridge%20selected/%C3%A9%23x%5Cy.html");
        assert!(file_url(Path::new("relative.html")).is_err());
    }
}
