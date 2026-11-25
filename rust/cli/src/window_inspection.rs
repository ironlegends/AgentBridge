//! Native window adapters share the existing public selection API.
//! Windows retains its original implementation and consent flow unchanged.
#[cfg(windows)]
#[path = "window_inspection/windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::{attach, confirm_local_selection, DedicatedWindow, LocalApproval};

#[cfg(any(not(windows), test))]
#[path = "window_inspection/portable.rs"]
mod portable;
#[cfg(not(windows))]
pub use portable::{attach, confirm_local_selection, DedicatedWindow, LocalApproval};
