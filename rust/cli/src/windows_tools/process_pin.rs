use crate::agent_desktop::NativeWindow;
use crate::runtime::RuntimeError;

#[cfg(windows)]
#[link(name="user32")]
extern "system" {
    fn IsWindow(hwnd:isize)->i32;
    fn GetWindowThreadProcessId(hwnd:isize,pid:*mut u32)->u32;
    fn GetClassNameW(hwnd:isize,name:*mut u16,maximum:i32)->i32;
}

// Independent, passive OS re-observation. A live process handle does not
// prove that a specific HWND is still alive or belongs to the same thread.
#[cfg(windows)]
fn verify_live_window(window:&NativeWindow)->Result<(),RuntimeError>{
    let hwnd=usize::try_from(window.hwnd).map_err(|_|"UI_WINDOW_HANDLE_INVALID")? as isize;
    if hwnd==0||unsafe{IsWindow(hwnd)}==0{return Err("UI_WINDOW_GONE".into());}
    let query=||{
        let mut pid=0;
        let tid=unsafe{GetWindowThreadProcessId(hwnd,&mut pid)};
        (pid,tid)
    };
    if query()!=(window.pid,window.tid){return Err("UI_WINDOW_OWNER_CHANGED".into());}
    let mut name=[0u16;2049];
    let count=unsafe{GetClassNameW(hwnd,name.as_mut_ptr(),name.len() as i32)};
    if count<=0 || count as usize>=name.len()-1{return Err("UI_WINDOW_CLASS_UNAVAILABLE".into());}
    if String::from_utf16(&name[..count as usize]).map_err(|_|"UI_WINDOW_CLASS_INVALID")?!=window.class_name {
        return Err("UI_WINDOW_CLASS_CHANGED".into());
    }
    if unsafe{IsWindow(hwnd)}==0||query()!=(window.pid,window.tid){return Err("UI_WINDOW_OWNER_CHANGED".into());}
    Ok(())
}

#[cfg(windows)]
pub(super) struct ProcessPin(std::os::windows::io::OwnedHandle);
#[cfg(not(windows))]
pub(super) struct ProcessPin;

impl ProcessPin {
    #[cfg(windows)]
    pub(super) fn open(window: &NativeWindow) -> Result<Self,RuntimeError> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::Threading::OpenProcess;
        let handle = unsafe { OpenProcess(0x1000 | 0x00100000,0,window.pid) };
        if handle.is_null() { return Err("UI_PROCESS_UNAVAILABLE".into()); }
        let pin = Self(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) });
        pin.verify(window)?; Ok(pin)
    }
    #[cfg(windows)]
    pub(super) fn verify(&self, window: &NativeWindow) -> Result<(),RuntimeError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::{GetProcessId,GetProcessTimes, QueryFullProcessImageNameW, WaitForSingleObject};
        let handle = self.0.as_raw_handle();
        verify_live_window(window)?;
        if unsafe{GetProcessId(handle)}!=window.pid{return Err("UI_PROCESS_IDENTITY_CHANGED".into());}
        let mut birth: FILETIME = unsafe { std::mem::zeroed() };
        let mut exit: FILETIME = unsafe { std::mem::zeroed() };
        let mut kernel: FILETIME = unsafe { std::mem::zeroed() };
        let mut user: FILETIME = unsafe { std::mem::zeroed() };
        if unsafe { WaitForSingleObject(handle,0) } != 0x102 || unsafe { GetProcessTimes(handle,&mut birth,&mut exit,&mut kernel,&mut user) } == 0 {
            return Err("UI_PROCESS_EXITED".into());
        }
        let born = ((birth.dwHighDateTime as u64)<<32)|birth.dwLowDateTime as u64;
        let mut image = vec![0u16;32768]; let mut size = image.len() as u32;
        if born != window.birth || unsafe { QueryFullProcessImageNameW(handle,0,image.as_mut_ptr(),&mut size) } == 0
            || !String::from_utf16(&image[..size as usize]).map_err(|_|"UI_PROCESS_IMAGE_INVALID")?.eq_ignore_ascii_case(&window.image) {
            return Err("UI_PROCESS_IDENTITY_CHANGED".into());
        }
        verify_live_window(window)?;
        if unsafe{WaitForSingleObject(handle,0)}!=0x102{return Err("UI_PROCESS_EXITED".into());}
        Ok(())
    }
    #[cfg(not(windows))]
    pub(super) fn open(_: &NativeWindow) -> Result<Self,RuntimeError> { Err("UI_WINDOWS_REQUIRED".into()) }
    #[cfg(not(windows))]
    pub(super) fn verify(&self,_: &NativeWindow) -> Result<(),RuntimeError> { Err("UI_WINDOWS_REQUIRED".into()) }
}

#[cfg(all(test,windows))]
mod tests {
    use super::*;
    use std::ptr;
    use windows_sys::Win32::{Foundation::FILETIME,System::Threading::{GetCurrentProcess,GetCurrentThreadId,GetProcessTimes,QueryFullProcessImageNameW}};
    #[link(name="user32")]
    extern "system" {
        fn CreateWindowExW(ex:u32,class:*const u16,title:*const u16,style:u32,x:i32,y:i32,w:i32,h:i32,parent:isize,menu:isize,instance:isize,param:*mut std::ffi::c_void)->isize;
        fn DestroyWindow(hwnd:isize)->i32;
        fn GetForegroundWindow()->isize;
        fn IsWindowVisible(hwnd:isize)->i32;
    }
    struct HiddenWindow(isize);
    impl Drop for HiddenWindow {fn drop(&mut self){if self.0!=0{unsafe{DestroyWindow(self.0);}}}}
    #[test]
    fn process_pin_rejects_destroyed_hwnd_even_while_process_remains_alive(){
        let foreground=unsafe{GetForegroundWindow()};
        let class="Static\0".encode_utf16().collect::<Vec<_>>();
        let title="Agent Bridge hidden identity fixture\0".encode_utf16().collect::<Vec<_>>();
        // HWND_MESSAGE: a message-only HWND, never shown or activated.
        let hwnd=unsafe{CreateWindowExW(0,class.as_ptr(),title.as_ptr(),0,0,0,0,0,-3,0,0,ptr::null_mut())};
        assert_ne!(hwnd,0,"hidden window: {}",std::io::Error::last_os_error());
        let mut owner=HiddenWindow(hwnd);
        assert_eq!(unsafe{IsWindowVisible(hwnd)},0);
        let process=unsafe{GetCurrentProcess()};
        let(mut birth,mut exit,mut kernel,mut user)=(FILETIME::default(),FILETIME::default(),FILETIME::default(),FILETIME::default());
        assert_ne!(unsafe{GetProcessTimes(process,&mut birth,&mut exit,&mut kernel,&mut user)},0);
        let mut image=vec![0u16;32768];let mut len=image.len() as u32;
        assert_ne!(unsafe{QueryFullProcessImageNameW(process,0,image.as_mut_ptr(),&mut len)},0);
        let witness=NativeWindow{hwnd:hwnd as usize as u64,pid:std::process::id(),tid:unsafe{GetCurrentThreadId()},
            birth:(u64::from(birth.dwHighDateTime)<<32)|u64::from(birth.dwLowDateTime),
            image:String::from_utf16(&image[..len as usize]).unwrap(),class_name:"Static".into(),
            title:"fixture".into(),left:0,top:0,width:0,height:0,foreground:false,visible:false,is_hud:false,
            desktop_id:"11111111-1111-4111-8111-111111111111".into(),desktop_number:2};
        let pin=ProcessPin::open(&witness).unwrap();
        pin.verify(&witness).unwrap();
        let mut wrong=witness.clone();wrong.tid=wrong.tid.wrapping_add(1);
        assert_eq!(pin.verify(&wrong).unwrap_err().to_string(),"UI_WINDOW_OWNER_CHANGED");
        let mut wrong=witness.clone();wrong.class_name="OtherClass".into();
        assert_eq!(pin.verify(&wrong).unwrap_err().to_string(),"UI_WINDOW_CLASS_CHANGED");
        assert_ne!(unsafe{DestroyWindow(hwnd)},0);owner.0=0;
        assert!(pin.verify(&witness).is_err(),"destroyed HWND accepted solely because its process remains alive");
        assert_eq!(unsafe{GetForegroundWindow()},foreground);
    }
}
