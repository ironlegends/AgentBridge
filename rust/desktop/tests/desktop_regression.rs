use agent_bridge_desktop::skills::{
    decode_zip_bytes, ApprovedRemoteProvider, PackageLimits, RawPackageFile, RemoteSourcePolicy,
    SkillError, SkillErrorCode, SkillManager, SkillManagerConfig,
};
use sha2::{Digest, Sha256};
use agent_bridge_desktop::{DesktopConfig, DesktopFiles, DesktopProfile};
use cap_std::ambient_authority;
use cap_std::fs::Dir;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let n = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = { let t = std::env::temp_dir(); if cfg!(unix) { std::fs::canonicalize(&t).unwrap_or(t) } else { t } }.join(format!(
            "ab-desktop-test-{}-{}-{}",
            label,
            std::process::id(),
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn call_tool(files: &DesktopFiles, name: &str, args: Value) -> (bool, Value) {
    let raw = files.dispatch(name, &args);
    let is_err = raw.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let text = raw["content"][0]["text"]
        .as_str()
        .expect("tool content text");
    let parsed: Value = serde_json::from_str(text).expect("tool JSON text");
    (is_err, parsed)
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("create zip");
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("start zip entry");
        writer.write_all(bytes).expect("write zip entry");
    }
    writer.finish().expect("finish zip");
}

#[test]
fn files_write_edit_move_search_and_observation_regressions() {
    let tmp = TempDir::new("files");
    let files = DesktopFiles::open(
        DesktopConfig::new(tmp.path())
            .with_session_profile(DesktopProfile::WorkspaceWrite)
            .allow_workspace_write(),
    )
    .expect("open writable desktop");

    // 1. Policy status
    let (err, pol) = call_tool(&files, "desktop_policy_status", json!({}));
    assert!(!err, "policy_status failed: {pol}");
    assert_eq!(pol["file_access"], "workspace-write");
    assert_eq!(pol["profile"], "workspace-write");

    // 2. Create directory & file
    let (err, cd) = call_tool(&files, "desktop_create_directory", json!({"path": "notes"}));
    assert!(!err && cd["created"] == true, "{cd}");

    let (err, wr) = call_tool(
        &files,
        "desktop_write_file",
        json!({"path": "notes/a.md", "content": "alpha\nbeta\n", "mode": "rewrite"}),
    );
    assert!(!err && wr["path"] == "notes/a.md", "{wr}");

    // 3. Read & append using single-use observation_id
    let (err, rd1) = call_tool(
        &files,
        "desktop_read_file",
        json!({"path": "notes/a.md", "offset": 0, "length": 100}),
    );
    assert!(!err, "{rd1}");
    let obs1 = rd1["observation_id"].as_str().expect("observation_id").to_owned();

    let (err, ap) = call_tool(
        &files,
        "desktop_write_file",
        json!({"path": "notes/a.md", "content": "gamma\n", "mode": "append", "observation_id": obs1}),
    );
    assert!(!err, "{ap}");

    // 4. Regression: reusing consumed observation_id must fail
    let (err, stale) = call_tool(
        &files,
        "desktop_edit_file",
        json!({
            "path": "notes/a.md",
            "old_string": "beta",
            "new_string": "BETA",
            "observation_id": obs1
        }),
    );
    assert!(err, "reusing consumed observation_id must fail: {stale}");

    // 5. Fresh read -> edit -> read -> move
    let (err, rd2) = call_tool(
        &files,
        "desktop_read_file",
        json!({"path": "notes/a.md", "offset": 0, "length": 100}),
    );
    assert!(!err && rd2["content"].as_str().unwrap().contains("gamma"), "{rd2}");
    let obs2 = rd2["observation_id"].as_str().unwrap().to_owned();

    let (err, ed) = call_tool(
        &files,
        "desktop_edit_file",
        json!({
            "path": "notes/a.md",
            "old_string": "beta",
            "new_string": "BETA",
            "expected_replacements": 1,
            "observation_id": obs2
        }),
    );
    assert!(!err, "{ed}");

    let (err, rd3) = call_tool(
        &files,
        "desktop_read_file",
        json!({"path": "notes/a.md", "offset": 0, "length": 100}),
    );
    assert!(!err, "{rd3}");
    let obs3 = rd3["observation_id"].as_str().unwrap().to_owned();

    let (err, mv) = call_tool(
        &files,
        "desktop_move_file",
        json!({"source": "notes/a.md", "destination": "notes/b.md", "source_observation_id": obs3}),
    );
    assert!(!err, "{mv}");

    // 6. Info, list, search
    let (err, info) = call_tool(&files, "desktop_get_file_info", json!({"path": "notes/b.md"}));
    assert!(!err && info["kind"] == "file", "{info}");

    let (err, list) = call_tool(&files, "desktop_list_directory", json!({"path": "notes", "depth": 1}));
    assert!(
        !err && list["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"].as_str().unwrap_or("").contains("b.md")),
        "{list}"
    );

    let (err, found) = call_tool(
        &files,
        "desktop_search",
        json!({"path": ".", "pattern": "BETA", "search_type": "content", "literal_search": true}),
    );
    assert!(!err && found["matches"].as_array().unwrap().len() == 1, "{found}");

    // 7. Regressions: traversal & absolute paths rejected
    let (err, trav) = call_tool(&files, "desktop_read_file", json!({"path": "../outside.txt"}));
    assert!(err, "traversal must be rejected: {trav}");
    let (err, abs) = call_tool(
        &files,
        "desktop_read_file",
        json!({"path": tmp.path().join("notes/b.md").to_string_lossy()}),
    );
    assert!(err, "absolute path must be rejected: {abs}");
}

#[test]
fn readonly_and_web_project_read_fail_closed_regressions() {
    let tmp = TempDir::new("ro-web");
    fs::write(tmp.path().join("public.txt"), "hello world\n").unwrap();
    fs::write(tmp.path().join(".env"), "SECRET=123\n").unwrap();
    fs::write(tmp.path().join("credentials.json"), "{}\n").unwrap();

    // Read-only profile excludes write tools & refuses artifact publish/delete
    let ro = DesktopFiles::open(
        DesktopConfig::new(tmp.path()).with_session_profile(DesktopProfile::ReadOnly),
    )
    .expect("open ro");
    let names: Vec<String> = ro.tool_catalog().into_iter().map(|t| t.name.to_owned()).collect();
    assert!(!names.contains(&"desktop_write_file".to_owned()));
    assert!(!names.contains(&"desktop_edit_file".to_owned()));
    assert!(!names.contains(&"desktop_move_file".to_owned()));
    assert!(!names.contains(&"desktop_create_directory".to_owned()));

    let (err, pub_ro) = call_tool(
        &ro,
        "desktop_artifact_manage",
        json!({"action": "publish", "path": "public.txt"}),
    );
    assert!(err && pub_ro["code"] == "READ_ONLY", "{pub_ro}");

    let (err, del_ro) = call_tool(
        &ro,
        "desktop_artifact_manage",
        json!({"action": "delete", "artifact_id": "art_00000000000000000000000000000000"}),
    );
    assert!(err && del_ro["code"] == "READ_ONLY", "{del_ro}");

    // Web project-read exposes only 4 tools and blocks secrets, dot-files, depth>1, content search
    let web = DesktopFiles::open(DesktopConfig::new(tmp.path()).with_web_project_read_policy())
        .expect("open web project-read");
    let web_names: Vec<String> = web.tool_catalog().into_iter().map(|t| t.name.to_owned()).collect();
    assert_eq!(web_names.len(), 4, "web project-read must expose exactly 4 tools: {web_names:?}");
    assert!(web_names.contains(&"desktop_read_file".to_owned()));
    assert!(web_names.contains(&"desktop_list_directory".to_owned()));
    assert!(web_names.contains(&"desktop_get_file_info".to_owned()));
    assert!(web_names.contains(&"desktop_search".to_owned()));

    let (err, env_res) = call_tool(&web, "desktop_read_file", json!({"path": ".env"}));
    assert!(err, ".env must be refused in web project-read: {env_res}");
    let (err, cred_res) = call_tool(&web, "desktop_read_file", json!({"path": "credentials.json"}));
    assert!(err, "credentials.json must be refused in web project-read: {cred_res}");
    let (err, depth_res) = call_tool(&web, "desktop_list_directory", json!({"path": ".", "depth": 2}));
    assert!(err, "depth=2 must be refused in web project-read: {depth_res}");
    let (err, content_res) = call_tool(
        &web,
        "desktop_search",
        json!({"path": ".", "pattern": "hello", "search_type": "content"}),
    );
    assert!(err, "content search must be refused in web project-read: {content_res}");
    let (err, ok_pub) = call_tool(&web, "desktop_read_file", json!({"path": "public.txt"}));
    assert!(!err && ok_pub["content"].as_str().unwrap().contains("hello"), "{ok_pub}");
}

#[test]
fn artifact_chunking_utf8_boundaries_binary_and_delete_regressions() {
    let tmp = TempDir::new("artifacts");
    let files = DesktopFiles::open(
        DesktopConfig::new(tmp.path())
            .with_session_profile(DesktopProfile::WorkspaceWrite)
            .allow_workspace_write(),
    )
    .expect("open writable");

    // "abcdéfg€hij" -> bytes: abcd (4), é (2), fg (2), € (3), hij (3) = 14 bytes
    let text = "abcdéfg€hij";
    fs::write(tmp.path().join("mb.txt"), text.as_bytes()).unwrap();
    let bin = b"\x89PNG\r\n\x1a\n\x00\xff\xfeBIN";
    fs::write(tmp.path().join("raw.bin"), bin).unwrap();

    // Publish UTF-8 file
    let (err, pub1) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "publish", "path": "mb.txt", "retention_seconds": 300}),
    );
    assert!(!err, "{pub1}");
    let art_id = pub1["artifact"]["artifact_id"].as_str().unwrap().to_owned();
    assert_eq!(pub1["artifact"]["size_bytes"], 14);

    // Cut inside 'é' (offset=0, length=5) -> trims to 4 bytes
    let (err, c1) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "read", "artifact_id": art_id, "encoding": "utf8", "offset": 0, "length": 5}),
    );
    assert!(!err, "{c1}");
    assert_eq!(c1["bytes_read"], 4);
    assert_eq!(c1["next_offset"], 4);
    assert_eq!(c1["content"], "abcd");
    assert_eq!(c1["eof"], false);
    assert_eq!(c1["has_more"], true);

    // Length=1 at start of 2-byte 'é' -> INVALID_UTF8_BOUNDARY
    let (err, bnd) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "read", "artifact_id": art_id, "encoding": "utf8", "offset": 4, "length": 1}),
    );
    assert!(err && bnd["code"] == "INVALID_UTF8_BOUNDARY", "{bnd}");

    // Read remainder + exact EOF + past-EOF INVALID_OFFSET
    let (err, c2) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "read", "artifact_id": art_id, "encoding": "utf8", "offset": 4, "length": 64}),
    );
    assert!(!err && c2["eof"] == true && format!("{}{}", c1["content"].as_str().unwrap(), c2["content"].as_str().unwrap()) == text, "{c2}");

    let (err, eof_read) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "read", "artifact_id": art_id, "encoding": "utf8", "offset": 14, "length": 10}),
    );
    assert!(!err && eof_read["bytes_read"] == 0 && eof_read["eof"] == true, "{eof_read}");

    let (err, past_eof) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "read", "artifact_id": art_id, "encoding": "utf8", "offset": 15, "length": 10}),
    );
    assert!(err && past_eof["code"] == "INVALID_OFFSET", "{past_eof}");

    // Binary file: utf8 rejected with INVALID_UTF8, base64 succeeds
    let (err, pub_bin) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "publish", "path": "raw.bin"}),
    );
    assert!(!err, "{pub_bin}");
    let bin_id = pub_bin["artifact"]["artifact_id"].as_str().unwrap().to_owned();

    let (err, bad_utf8) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "read", "artifact_id": bin_id, "encoding": "utf8", "offset": 0, "length": 64}),
    );
    assert!(err && bad_utf8["code"] == "INVALID_UTF8", "{bad_utf8}");

    let (err, ok_b64) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "read", "artifact_id": bin_id, "encoding": "base64", "offset": 0, "length": 64}),
    );
    assert!(!err && ok_b64["bytes_read"] == bin.len() && ok_b64["eof"] == true, "{ok_b64}");

    // Delete & verify ARTIFACT_NOT_FOUND
    let (err, del) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "delete", "artifact_id": art_id}),
    );
    assert!(!err && del["deleted"] == true, "{del}");

    let (err, missing) = call_tool(
        &files,
        "desktop_artifact_manage",
        json!({"action": "get", "artifact_id": art_id}),
    );
    assert!(err && missing["code"] == "ARTIFACT_NOT_FOUND", "{missing}");
}

#[test]
fn skills_all_7_local_actions_and_remote_gap_regressions() {
    let tmp = TempDir::new("skills");
    let ws = tmp.path().join("ws");
    let store = tmp.path().join("store");
    fs::create_dir_all(ws.join("sk1")).unwrap();
    fs::create_dir_all(ws.join("sk2")).unwrap();
    fs::create_dir_all(&store).unwrap();

    fs::write(
        ws.join("sk1/SKILL.md"),
        "---\nname: sample-skill\ndescription: v1\nversion: 0.1.0\n---\n# Version 1\n",
    )
    .unwrap();
    fs::write(
        ws.join("sk2/SKILL.md"),
        "---\nname: sample-skill\ndescription: v2\nversion: 0.2.0\n---\n# Version 2\n",
    )
    .unwrap();

    let files = DesktopFiles::open(
        DesktopConfig::new(&ws)
            .with_session_profile(DesktopProfile::WorkspaceWrite)
            .allow_workspace_write(),
    )
    .expect("open desktop");
    let mgr = files.documentary_skills(&store).expect("skill manager");

    // 1. validate, install v1, list, get, read
    let v = mgr
        .dispatch(&json!({"action": "validate", "source_path": "sk1", "name": "sample-skill"}))
        .expect("validate");
    assert_eq!(v["valid"], true);

    let i1 = mgr
        .dispatch(&json!({"action": "install", "source_path": "sk1", "name": "sample-skill", "activate": true}))
        .expect("install v1");
    let v1 = i1["version"].as_str().unwrap().to_owned();
    assert_eq!(i1["active_version"], v1);

    // Gap/edge regression: rollback with only one version must fail cleanly
    let rb_err = mgr
        .dispatch(&json!({"action": "rollback", "name": "sample-skill"}))
        .expect_err("rollback with single version must fail");
    assert_eq!(rb_err.code, SkillErrorCode::NoRollbackTarget);

    let listed = mgr
        .dispatch(&json!({"action": "list", "name": "sample-skill"}))
        .expect("list");
    assert_eq!(listed["skills"].as_array().unwrap().len(), 1);

    let got = mgr
        .dispatch(&json!({"action": "get", "name": "sample-skill"}))
        .expect("get");
    assert_eq!(got["active_version"], v1);

    let r1 = mgr
        .dispatch(&json!({"action": "read", "name": "sample-skill"}))
        .expect("read v1");
    assert!(r1["content"].as_str().unwrap().contains("Version 1"));

    // 2. install v2 inactive -> activate -> read v2 -> rollback -> read v1
    let i2 = mgr
        .dispatch(&json!({"action": "install", "source_path": "sk2", "name": "sample-skill", "activate": false}))
        .expect("install v2");
    let v2 = i2["version"].as_str().unwrap().to_owned();
    assert_eq!(i2["active_version"], v1);

    let act = mgr
        .dispatch(&json!({"action": "activate", "name": "sample-skill", "version": v2}))
        .expect("activate v2");
    assert_eq!(act["active_version"], v2);
    let r2 = mgr
        .dispatch(&json!({"action": "read", "name": "sample-skill"}))
        .expect("read v2");
    assert!(r2["content"].as_str().unwrap().contains("Version 2"));

    let rb = mgr
        .dispatch(&json!({"action": "rollback", "name": "sample-skill"}))
        .expect("rollback to v1");
    assert_eq!(rb["active_version"], v1);
    let r1_again = mgr
        .dispatch(&json!({"action": "read", "name": "sample-skill"}))
        .expect("read v1 after rollback");
    assert!(r1_again["content"].as_str().unwrap().contains("Version 1"));

    // 3. Local ZIP install + traversal ZIP rejection
    write_zip(
        &ws.join("good.zip"),
        &[(
            "SKILL.md",
            b"---\nname: zip-ok\ndescription: ok\nversion: 1.0.0\n---\n# Zip\n",
        )],
    );
    let z_ok = mgr
        .dispatch(&json!({"action": "install", "source_path": "good.zip", "name": "zip-ok", "activate": true}))
        .expect("zip install");
    assert_eq!(z_ok["ok"], true);

    write_zip(
        &ws.join("evil.zip"),
        &[
            (
                "SKILL.md",
                b"---\nname: zip-bad\ndescription: bad\nversion: 1.0.0\n---\n# Bad\n",
            ),
            ("../escape.txt", b"nope"),
        ],
    );
    let z_bad = mgr
        .dispatch(&json!({"action": "install", "source_path": "evil.zip", "name": "zip-bad"}))
        .expect_err("ZIP traversal must be rejected");
    assert!(matches!(
        z_bad.code,
        SkillErrorCode::PathPolicyViolation | SkillErrorCode::ValidationFailed | SkillErrorCode::InvalidInput
    ));

    // 4. EXPLICIT GAP REGRESSIONS: remote source_url fail-closed checks
    // 4a. Default policy (full_unlock_enabled=false) refuses remote source_url
    let e_default = mgr
        .dispatch(&json!({
            "action": "install",
            "source_url": "https://skills.example.test/pkg.zip",
            "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .expect_err("remote source_url must be denied by default");
    assert_eq!(e_default.code, SkillErrorCode::RemoteRequiresFullUnlock);

    // 4b. Full/Unlock enabled + allowlisted origin, but NO ApprovedRemoteProvider configured (current gap)
    let mut cfg = SkillManagerConfig::for_operator("tester");
    cfg.limits = PackageLimits::default();
    cfg.remote_policy = RemoteSourcePolicy {
        full_unlock_enabled: true,
        allowed_https_origins: vec!["https://skills.example.test".to_owned()],
        max_archive_bytes: 1024 * 1024,
    };
    let store_dir = Dir::open_ambient_dir(&store, ambient_authority()).unwrap();
    let ws_dir = Dir::open_ambient_dir(&ws, ambient_authority()).unwrap();
    let remote_mgr = SkillManager::new(store_dir, ws_dir, cfg).expect("remote_mgr");

    // Non-HTTPS rejected
    let e_http = remote_mgr
        .dispatch(&json!({
            "action": "install",
            "source_url": "http://skills.example.test/pkg.zip",
            "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .expect_err("http source_url must be rejected");
    assert_eq!(e_http.code, SkillErrorCode::PathPolicyViolation);

    // Missing expected_sha256 rejected
    let e_nosha = remote_mgr
        .dispatch(&json!({
            "action": "install",
            "source_url": "https://skills.example.test/pkg.zip"
        }))
        .expect_err("missing expected_sha256 must be rejected");
    assert_eq!(e_nosha.code, SkillErrorCode::InvalidInput);

    // Non-allowlisted origin rejected
    let e_origin = remote_mgr
        .dispatch(&json!({
            "action": "install",
            "source_url": "https://other.example.test/pkg.zip",
            "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .expect_err("unlisted origin must be rejected");
    assert_eq!(e_origin.code, SkillErrorCode::RemoteOriginNotAllowed);

    // Allowlisted origin with no configured ApprovedRemoteProvider -> explicit NotAvailable / PolicyDenied
    let e_noprovider = remote_mgr
        .dispatch(&json!({
            "action": "install",
            "source_url": "https://skills.example.test/pkg.zip",
            "expected_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .expect_err("missing remote provider must fail closed");
    assert!(
        e_noprovider
            .message
            .contains("no ApprovedRemoteProvider is configured"),
        "unexpected error: {e_noprovider:?}"
    );
}

struct InMemoryRemoteProvider {
    expected_url: String,
    payload: Vec<u8>,
}

impl ApprovedRemoteProvider for InMemoryRemoteProvider {
    fn fetch_zip_bytes(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, SkillError> {
        if url != self.expected_url {
            return Err(SkillError::new(SkillErrorCode::NotFound, "unexpected url"));
        }
        if self.payload.len() > max_bytes {
            return Err(SkillError::new(SkillErrorCode::LimitExceeded, "payload too large"));
        }
        Ok(self.payload.clone())
    }

    fn extract_zip_entries(
        &self,
        zip_bytes: &[u8],
        limits: &PackageLimits,
    ) -> Result<Vec<RawPackageFile>, SkillError> {
        decode_zip_bytes(zip_bytes, limits)
    }
}

#[test]
fn skills_remote_provider_verified_sha256_and_mismatch_regressions() {
    let tmp = TempDir::new("remote-skills");
    let ws = tmp.path().join("ws");
    let store = tmp.path().join("store");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&store).unwrap();

    let zip_path = tmp.path().join("remote-demo.zip");
    write_zip(
        &zip_path,
        &[(
            "SKILL.md",
            b"---\nname: remote-demo\ndescription: verified remote skill\nversion: 1.0.0\n---\n# Remote Body\n",
        )],
    );
    let zip_bytes = fs::read(&zip_path).unwrap();
    let expected_sha: String = Sha256::digest(&zip_bytes).iter().map(|b| format!("{b:02x}")).collect();
    let url = "https://skills.example.test/packages/remote-demo.zip";

    let files = DesktopFiles::open(
        DesktopConfig::new(&ws)
            .with_session_profile(DesktopProfile::FullControl)
            .allow_workspace_write(),
    )
    .expect("open full-control desktop");

    let policy = RemoteSourcePolicy {
        full_unlock_enabled: true,
        allowed_https_origins: vec!["https://skills.example.test".to_owned()],
        max_archive_bytes: 1024 * 1024,
    };
    let provider = Box::new(InMemoryRemoteProvider {
        expected_url: url.to_owned(),
        payload: zip_bytes.clone(),
    });
    let mgr = files
        .documentary_skills_with_policy(&store, policy.clone(), Some(provider))
        .expect("documentary_skills_with_policy");

    // 1. Wrong SHA-256 fails closed with DigestMismatch
    let bad_sha = "0".repeat(64);
    let err = mgr
        .dispatch(&json!({
            "action": "install",
            "source_url": url,
            "expected_sha256": bad_sha
        }))
        .expect_err("wrong sha256 must fail");
    assert_eq!(err.code, SkillErrorCode::DigestMismatch);

    // 2. Exact SHA-256 validates, installs, and reads cleanly
    let validated = mgr
        .dispatch(&json!({
            "action": "validate",
            "source_url": url,
            "expected_sha256": expected_sha
        }))
        .expect("validate remote zip");
    assert_eq!(validated["valid"], true);

    let installed = mgr
        .dispatch(&json!({
            "action": "install",
            "source_url": url,
            "expected_sha256": expected_sha,
            "activate": true
        }))
        .expect("install remote zip");
    assert_eq!(installed["ok"], true);

    let read = mgr
        .dispatch(&json!({"action": "read", "name": "remote-demo"}))
        .expect("read remote skill");
    assert!(read["content"].as_str().unwrap().contains("Remote Body"));

    // 3. Oversized archive fails closed with LimitExceeded
    let tiny_policy = RemoteSourcePolicy {
        full_unlock_enabled: true,
        allowed_https_origins: vec!["https://skills.example.test".to_owned()],
        max_archive_bytes: 16,
    };
    let mgr_tiny = files
        .documentary_skills_with_policy(
            &store,
            tiny_policy,
            Some(Box::new(InMemoryRemoteProvider {
                expected_url: url.to_owned(),
                payload: zip_bytes,
            })),
        )
        .expect("tiny mgr");
    let err_sz = mgr_tiny
        .dispatch(&json!({
            "action": "install",
            "source_url": url,
            "expected_sha256": expected_sha
        }))
        .expect_err("oversized remote zip must fail");
    assert_eq!(err_sz.code, SkillErrorCode::LimitExceeded);
}


fn write_import_skill(root: &Path, package: &str, name: &str, version: &str, body: &str) {
    let dir = root.join(package);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("SKILL.md"), format!(
        "---\nname: {name}\ndescription: Synthetic documentary skill\nversion: {version}\nlicense: Apache-2.0\n---\n{body}\n"
    )).unwrap();
}

#[test]
fn operator_skill_import_reuses_seven_actions_and_immutable_provenance() {
    let tmp=TempDir::new("operator-skill");
    let root=tmp.path().join(".agents/skills");
    let alternate=tmp.path().join(".claude/skills");
    let store=tmp.path().join("store");
    fs::create_dir_all(&store).unwrap();
    write_import_skill(&root,"demo","demo","1","First revision");
    write_import_skill(&alternate,"demo","demo","1","First revision");
    let dir=root.join("demo");
    fs::create_dir_all(dir.join("references")).unwrap();
    fs::create_dir_all(dir.join("scripts")).unwrap();
    fs::write(dir.join("references/readme.md"),"éclair fixture").unwrap();
    fs::write(dir.join("scripts/example.py"),"raise RuntimeError('documentary only')\n").unwrap();
    fs::write(dir.join("LICENSE"),"Synthetic license witness").unwrap();
    let discovered=SkillManager::discover_operator_root(&root,||true).unwrap();
    assert_eq!(discovered["candidates"],json!(["demo"]));
    assert!(!discovered.to_string().contains(&root.display().to_string()));
    assert!(SkillManager::discover_operator_root(&root,||false).is_err());
    assert!(SkillManager::import_operator_directory(&store,&root,"demo",true,
        ||false, |_|panic!("declined source must not be read")).is_err());
    assert!(SkillManager::import_operator_directory(&store,&root,"demo",true,
        ||true, |_|false).is_err());
    assert!(!store.join("registry.json").exists());
    let first=SkillManager::import_operator_directory(&store,&root,"demo",true,||true,|preview|{
        assert_eq!(preview["source_kind"],"operator_approved_directory");
        assert_eq!(preview["license"],"Apache-2.0");
        assert_eq!(preview["file_count"],4);
        assert_eq!(preview["bundled_scripts"],json!(["scripts/example.py"]));
        true
    }).unwrap();
    let version=first["version"].as_str().unwrap().to_owned();
    assert_eq!(first["active_version"],version);
    assert_eq!(first["license"],"Apache-2.0");
    let original_registry=fs::read(store.join("registry.json")).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&original_registry).unwrap()["schema_version"],2);
    let repeated=SkillManager::import_operator_directory(&store,&root,"demo",true,||true,|_|true).unwrap();
    assert_eq!(repeated["already_installed"],true);
    assert_eq!(repeated["activated"],false);
    assert_eq!(fs::read(store.join("registry.json")).unwrap(),original_registry);

    // A separate manager created by the existing tool path sees the same
    // store; the external directory is not in its workspace capability.
    let work=tmp.path().join("workspace");
    fs::create_dir_all(&work).unwrap();
    let files=DesktopFiles::open(DesktopConfig::new(&work)).unwrap();
    let mgr=files.documentary_skills(&store).unwrap();
    let listed=mgr.dispatch(&json!({"action":"list"})).unwrap();
    assert_eq!(listed["skills"][0]["name"],"demo");
    let got=mgr.dispatch(&json!({"action":"get","name":"demo"})).unwrap();
    assert_eq!(got["manifest"]["license"],"Apache-2.0");
    assert_eq!(got["manifest"]["source_ref"],first["source_ref"]);
    assert_eq!(got["manifest"]["version"],version);
    assert!(!got.to_string().contains(&root.display().to_string()));
    assert!(got["manifest"]["files"].as_array().unwrap().iter()
        .any(|entry|entry["path"]=="LICENSE"));
    let resource=mgr.dispatch(&json!({"action":"read","name":"demo","version":version,
        "resource_path":"references/readme.md","max_chars":3})).unwrap();
    assert_eq!(resource["content"],"écl");
    assert_eq!(resource["truncated"],true);
    let script=mgr.dispatch(&json!({"action":"read","name":"demo","resource_path":"scripts/example.py"})).unwrap();
    assert_eq!(script["is_script_document"],true);
    assert_eq!(script["execution_policy"],"never_executed");
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        let path=store.join("skills/demo/revisions").join(version.strip_prefix("sha256:").unwrap())
            .join("files/scripts/example.py");
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o111,0);
    }
    assert_eq!(mgr.dispatch(&json!({"action":"validate","name":"demo"})).unwrap()["valid"],true);
    assert!(mgr.dispatch(&json!({"action":"validate","source_path":root.join("demo")})).is_err());
    assert!(SkillManager::import_operator_directory(&store,&alternate,"demo",true,||true,|_|true).is_err());
    write_import_skill(&work,"demo","demo","3","Foreign workspace");
    assert!(mgr.dispatch(&json!({"action":"install","source_path":"demo"})).is_err());

    // Snapshot approval binds the actual loaded bytes, not a second read.
    write_import_skill(&root,"demo","demo","2","Second approved revision");
    let second=SkillManager::import_operator_directory(&store,&root,"demo",false,||true,|_|{
        write_import_skill(&root,"demo","demo","3","Changed after approval");
        true
    }).unwrap();
    let v2=second["version"].as_str().unwrap();
    assert_ne!(v2,version);
    assert_eq!(second["active_version"],version);
    mgr.dispatch(&json!({"action":"activate","name":"demo","version":v2})).unwrap();
    let text=mgr.dispatch(&json!({"action":"read","name":"demo"})).unwrap();
    assert!(text["content"].as_str().unwrap().contains("Second approved revision"));
    assert!(!text["content"].as_str().unwrap().contains("Changed after approval"));
    assert_eq!(mgr.dispatch(&json!({"action":"rollback","name":"demo"})).unwrap()["active_version"],version);
    assert!(SkillManager::revoke_operator_import(&store,"demo",||false).is_err());
    assert_eq!(SkillManager::revoke_operator_import(&store,"demo",||true).unwrap()["changed"],true);
    assert_eq!(SkillManager::revoke_operator_import(&store,"demo",||true).unwrap()["changed"],false);
    let reopened=files.documentary_skills(&store).unwrap();
    assert_eq!(reopened.dispatch(&json!({"action":"list"})).unwrap()["count"],0);
    for action in ["get","read","validate","activate","rollback"] {
        assert!(reopened.dispatch(&json!({"action":action,"name":"demo","version":version})).is_err(),
            "revoked revision exposed by {action}");
    }
    assert!(reopened.dispatch(&json!({"action":"install","source_path":"demo"})).is_err());
    assert!(SkillManager::import_operator_directory(&store,&root,"demo",true,||true,|_|true).is_err());
    write_import_skill(&root,"demo","renamed","4","Renamed revoked source");
    assert!(SkillManager::import_operator_directory(&store,&root,"demo",true,||true,|_|true).is_err());
    assert!(dir.join("SKILL.md").exists());
}

#[test]
fn operator_skill_import_refuses_traversal_collisions_and_size_budgets() {
    let tmp=TempDir::new("operator-skill-bounds");
    let root=tmp.path().join("source");
    let store=tmp.path().join("store");
    fs::create_dir_all(&store).unwrap();
    write_import_skill(&root,"good","demo","1","Example");
    let import=|name:&str| SkillManager::import_operator_directory(&store,&root,name,false,||true,|_|true);
    for bad in ["../good","good/../good","good\\references",".","..","/good","C:good",".hidden"] {
        assert!(import(bad).is_err(),"{bad}");
    }
    let dir=root.join("good");
    fs::write(dir.join("SKILL.md"),vec![b'a';512*1024+1]).unwrap();
    assert_eq!(import("good").unwrap_err().code,SkillErrorCode::LimitExceeded);
    write_import_skill(&root,"good","demo","1","Example");
    fs::write(dir.join(".env"),"synthetic-do-not-read").unwrap();
    assert!(import("good").is_err());
    fs::remove_file(dir.join(".env")).unwrap();
    fs::write(dir.join("blob.exe"),b"synthetic").unwrap();
    assert!(import("good").is_err());
    fs::remove_file(dir.join("blob.exe")).unwrap();
    fs::write(dir.join("too-large.md"),vec![b'a';2*1024*1024+1]).unwrap();
    assert_eq!(import("good").unwrap_err().code,SkillErrorCode::LimitExceeded);
    fs::remove_file(dir.join("too-large.md")).unwrap();
    for i in 0..256 { fs::write(dir.join(format!("ref-{i}.md")),"fixture").unwrap(); }
    assert_eq!(import("good").unwrap_err().code,SkillErrorCode::LimitExceeded);
    for i in 0..256 { fs::remove_file(dir.join(format!("ref-{i}.md"))).unwrap(); }
    #[cfg(unix)] {
        // Windows case-insensitive filesystems cannot create both names;
        // the shared assembler rejects these on any case-sensitive host.
        fs::write(dir.join("Resource.md"),"a").unwrap();
        match fs::OpenOptions::new().write(true).create_new(true).open(dir.join("resource.md")) {
            Ok(mut file) => {
                file.write_all(b"b").unwrap();
                drop(file);
                assert!(import("good").is_err());
                fs::remove_file(dir.join("resource.md")).unwrap();
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists),
        }
        fs::remove_file(dir.join("Resource.md")).unwrap();
    }
    let mut deep=dir.clone();
    for _ in 0..9 { deep=deep.join("nested"); }
    fs::create_dir_all(&deep).unwrap();
    fs::write(deep.join("ref.md"),"fixture").unwrap();
    assert_eq!(import("good").unwrap_err().code,SkillErrorCode::LimitExceeded);
    fs::remove_dir_all(dir.join("nested")).unwrap();
    let chunk=vec![b'a';2*1024*1024];
    for i in 0..8 { fs::write(dir.join(format!("large-{i}.md")),&chunk).unwrap(); }
    assert_eq!(import("good").unwrap_err().code,SkillErrorCode::LimitExceeded);
    for i in 0..8 { fs::remove_file(dir.join(format!("large-{i}.md"))).unwrap(); }
    for i in 0..257 { fs::create_dir(root.join(format!("empty-{i}"))).unwrap(); }
    assert_eq!(SkillManager::discover_operator_root(&root,||true).unwrap_err().code,SkillErrorCode::LimitExceeded);
    assert!(!store.join("registry.json").exists());
}

#[cfg(unix)]
#[test]
fn operator_skill_import_refuses_linked_root_child_and_resources() {
    use std::os::unix::fs::symlink;
    let tmp=TempDir::new("operator-skill-links");
    let root=tmp.path().join("root");
    let store=tmp.path().join("store");
    let outside=tmp.path().join("outside");
    fs::create_dir_all(&store).unwrap();
    write_import_skill(&root,"good","demo","1","Example");
    write_import_skill(&outside,"target","outside","1","Synthetic outside");
    symlink(outside.join("target"),root.join("linked")).unwrap();
    let linked_root=tmp.path().join("linked-root");
    symlink(&root,&linked_root).unwrap();
    let import=|root:&Path,child:&str| SkillManager::import_operator_directory(&store,root,child,false,||true,|_|true);
    assert!(import(&linked_root,"good").is_err());
    assert!(import(&root,"linked").is_err());
    symlink(outside.join("target/SKILL.md"),root.join("good/reference.md")).unwrap();
    assert!(import(&root,"good").is_err());
    fs::remove_file(root.join("good/reference.md")).unwrap();
    fs::hard_link(outside.join("target/SKILL.md"),root.join("good/reference.md")).unwrap();
    assert!(import(&root,"good").is_err());
    assert!(!store.join("registry.json").exists());
}

#[cfg(windows)]
#[test]
fn operator_skill_import_refuses_windows_junction() {
    use std::os::windows::process::CommandExt;
    let tmp=TempDir::new("operator-skill-junction");
    let root=tmp.path().join("root");
    let store=tmp.path().join("store");
    let outside=tmp.path().join("outside");
    fs::create_dir_all(&store).unwrap();
    write_import_skill(&root,"good","demo","1","Example");
    write_import_skill(&outside,"target","outside","1","Synthetic outside");
    let junction=root.join("linked");
    let target=outside.join("target");
    // A fixture-only junction requires no elevation. Refuse shell
    // metacharacters in the synthetic temp paths; never use package input.
    for path in [&junction,&target] {
        assert!(!path.to_str().unwrap().chars().any(|c|matches!(c,'&'|'|'|'<'|'>'|'^'|'%'|'!'|'"'|'\r'|'\n')));
    }
    let output=std::process::Command::new("cmd.exe").args(["/d","/v:off","/c","mklink","/J"])
        .arg(&junction).arg(&target).creation_flags(0x0800_0000).output().unwrap();
    assert!(output.status.success(),"junction fixture creation failed");
    let result=SkillManager::import_operator_directory(&store,&root,"linked",false,||true,|_|true);
    fs::remove_dir(&junction).unwrap();
    assert!(result.is_err());
    assert!(!store.join("registry.json").exists());
}

#[test]
fn operator_skill_import_preserves_legacy_records_and_refuses_revocation_downgrade() {
    let tmp=TempDir::new("operator-skill-v1-v2");
    let root=tmp.path().join("root");
    let workspace=tmp.path().join("workspace");
    let store=tmp.path().join("store");
    fs::create_dir_all(&store).unwrap();
    write_import_skill(&workspace,"legacy","legacy","1","Legacy source");
    write_import_skill(&root,"collision","legacy","2","Foreign legacy replacement");
    write_import_skill(&root,"approved","approved","1","Approved source");
    let desktop=DesktopFiles::open(DesktopConfig::new(&workspace)).unwrap();
    let mgr=desktop.documentary_skills(&store).unwrap();
    mgr.dispatch(&json!({"action":"install","source_path":"legacy"})).unwrap();
    let original=fs::read(store.join("registry.json")).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&original).unwrap()["schema_version"],1);
    assert!(SkillManager::import_operator_directory(&store,&root,"collision",true,||true,|_|true).is_err());
    assert_eq!(fs::read(store.join("registry.json")).unwrap(),original);
    SkillManager::import_operator_directory(&store,&root,"approved",true,||true,|_|true).unwrap();
    assert_eq!(mgr.dispatch(&json!({"action":"list"})).unwrap()["count"],2);
    assert!(mgr.dispatch(&json!({"action":"read","name":"legacy"})).unwrap()["content"]
        .as_str().unwrap().contains("Legacy source"));
    assert!(SkillManager::revoke_operator_import(&store,"legacy",||true).is_err());
    SkillManager::revoke_operator_import(&store,"approved",||true).unwrap();
    assert_eq!(mgr.dispatch(&json!({"action":"list"})).unwrap()["count"],1);
    // A V1 marker over V2 fields must not erase a tombstone silently.
    let mut registry:Value=serde_json::from_slice(&fs::read(store.join("registry.json")).unwrap()).unwrap();
    registry["schema_version"]=json!(1);
    fs::write(store.join("registry.json"),serde_json::to_vec(&registry).unwrap()).unwrap();
    assert_eq!(mgr.dispatch(&json!({"action":"list"})).unwrap_err().code,SkillErrorCode::CorruptStore);
}
