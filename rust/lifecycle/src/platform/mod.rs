#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::{
    create_private_directory, is_reparse, observe_process, private_open_options, self_birth,
    verify_private_directory, verify_private_file, verify_private_handle, wait_process_exit,
};
#[cfg(windows)]
pub(crate) use windows::private_directory_sddl;
#[cfg(windows)]
pub(crate) use windows::{
    create_private_directory, is_reparse, observe_process, private_open_options, self_birth,
    verify_private_directory, verify_private_file, verify_private_handle, wait_process_exit,
};
