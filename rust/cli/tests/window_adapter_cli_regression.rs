#![cfg(target_os = "linux")]

use agent_bridge_core::CoreDatabase;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Command,Stdio};
use std::time::{Duration,Instant};

struct Fixture(PathBuf);
impl Drop for Fixture {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}

#[test]
fn local_window_cli_refuses_headless_wayland_remote_and_mismatched_displays_before_consent() {
    let home=PathBuf::from(std::env::var_os("HOME").expect("native CLI test has a user home"));
    let root=Fixture(home.join(format!(".ab-window-cli-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())));
    fs::DirBuilder::new().mode(0o700).create(&root.0).unwrap();
    let project=root.0.join("project");let database_dir=root.0.join("db");
    fs::create_dir(&project).unwrap();fs::create_dir(&database_dir).unwrap();
    let database=database_dir.join("fixture.sqlite");
    drop(CoreDatabase::initialize_new(&database).unwrap());
    let binary=fs::canonicalize(env!("CARGO_BIN_EXE_agent-bridge")).unwrap();
    for (selection,display,wayland,expected) in [
        ("x11:0",None,None,"WINDOW_GRAPHICAL_SESSION_REQUIRED"),
        ("x11:0",Some("remote.invalid:0"),Some("wayland-fixture"),"WINDOW_WAYLAND_UNSUPPORTED"),
        ("x11:0",Some("remote.invalid:0"),None,"WINDOW_LOCAL_X11_REQUIRED"),
        ("x11:43",Some(":42"),None,"WINDOW_DISPLAY_MISMATCH"),
    ] {
        let mut command=Command::new(&binary);
        command.arg("stdio").arg(&database).arg("--workspace").arg(&project)
            .arg("--local-window-read").arg(selection).arg(&binary).arg("NeverConsentFixture").arg("No real target")
            .env_remove("DISPLAY").env_remove("WAYLAND_DISPLAY").env_remove("XDG_SESSION_TYPE")
            .env("AGENT_BRIDGE_DESKTOP_PROFILE","full-control").env_remove("AGENT_BRIDGE_DESKTOP_PROFILE_LOCK")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(display)=display{command.env("DISPLAY",display);}
        if let Some(wayland)=wayland{command.env("WAYLAND_DISPLAY",wayland);}
        let mut child=command.spawn().unwrap();let deadline=Instant::now()+Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_))=>break,
                Ok(None) if Instant::now()<deadline=>std::thread::sleep(Duration::from_millis(20)),
                _=>{let _=child.kill();let _=child.wait();panic!("window preflight must not open a consent dialog or wait for a display");}
            }
        }
        let output=child.wait_with_output().unwrap();
        assert!(!output.status.success(),"{expected}");
        assert!(output.stdout.is_empty(),"no tools are exposed before local consent");
        let diagnostic=String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains(expected),"expected {expected}, got {diagnostic}");
    }
}
