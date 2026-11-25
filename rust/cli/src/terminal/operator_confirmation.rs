//! Local Windows consent only. No Web/MCP approval route exists.
//! The entire executable path, SHA-256, arguments and CWD are displayed
//! before a single-use permit may be consumed. This module never launches
//! anything or reads project/private data.

use agent_bridge_commands::PendingApprovalView;

#[cfg(windows)]
pub(super) fn confirm(view: &PendingApprovalView) -> Result<bool, &'static str> {

    // Use the universally available USER32 Yes/No dialog. Requiring the
    // ComCtl32 v6 TaskDialogIndirect import broke process startup on Windows
    // systems where the executable does not activate that common-control
    // assembly. No DLL is loaded dynamically, no new service is installed.
    #[link(name="user32")]
    extern "system" {
        fn MessageBoxW(
            window:isize, content:*const u16, title:*const u16, flags:u32,
        ) -> i32;
    }
    const MB_YESNO:u32=0x0004;
    const MB_ICONWARNING:u32=0x0030;
    const MB_DEFBUTTON2:u32=0x0100; // NO, never Yes
    const MB_TOPMOST:u32=0x0004_0000;
    const ID_YES:i32=6;
    fn wide(s:&str)->Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let encoded_args=serde_json::to_string(&view.args)
        .map_err(|_|"PROCESS_APPROVAL_DISPLAY_REFUSED: cannot encode exact args")?;
    let text=format!(
        "LOCAL APPROVAL REQUIRED - one restricted project program\n\n\
         Exact executable: {}\nSHA-256: {}\nImage length: {}\n\
         Exact arguments (JSON array): {}\nExact working directory: {}\n\
         One-use confirmation digest: {}\n\n\
         YES permits one attempt only after all restricted-token checks. \
         NO is the default and cancels. The approval itself expires after \
         60 seconds; an expired approval cannot launch the program.",
        view.executable_path, view.executable_sha256,
        view.executable_identity.file_len, encoded_args,
        view.cwd, view.confirmation_digest,
    );
    // A partially displayed command MUST NOT acquire a valid confirmation.
    if text.len()>10_000 || text.contains('\0') {
        return Err("PROCESS_APPROVAL_DISPLAY_REFUSED: exact program details too long");
    }
    let title=wide("Agent Bridge - local project command approval");
    let body=wide(&text);
    let response=unsafe {
        MessageBoxW(0,body.as_ptr(),title.as_ptr(),
            MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2|MB_TOPMOST)
    };
    if response==0 {
        return Err("PROCESS_APPROVAL_UNAVAILABLE: native operator dialog failed");
    }
    Ok(response==ID_YES)
}

#[cfg(not(windows))]
pub(super) fn confirm(_view:&PendingApprovalView)->Result<bool,&'static str> {
    Err("PROCESS_APPROVAL_UNAVAILABLE: local confirmation requires Windows")
}
