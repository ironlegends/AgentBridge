//! Visible blue safety HUD on the already named, NON-PERSONAL Win32 desktop.
//! The lease owner thread binds this exact desktop before creating any window.
//! No SwitchDesktop, foreground activation, screen capture or elevation.
use super::*;
use std::ffi::c_void;
use std::time::{Duration, Instant};

type Wndproc = unsafe extern "system" fn(Hwnd,u32,usize,isize)->isize;
const WS_EX_TOPMOST:u32=0x0000_0008;
const WS_EX_TRANSPARENT:u32=0x0000_0020;
const WS_EX_TOOLWINDOW:u32=0x0000_0080;
const WS_EX_NOACTIVATE:u32=0x0800_0000;
const WS_POPUP:u32=0x8000_0000;
const WS_VISIBLE:u32=0x1000_0000;
const PM_REMOVE:u32=0x0001;
const WM_PAINT:u32=0x000f;
const DT_CENTER:u32=0x0001;
const DT_VCENTER:u32=0x0004;
const DT_SINGLELINE:u32=0x0020;
const TRANSPARENT:i32=1;
#[repr(C)]
struct WndClass {
    style:u32, callback:Option<Wndproc>, extra_class:i32,extra_window:i32,
    instance:Handle, icon:Handle,cursor:Handle,background:Handle,
    menu:*const u16,name:*const u16,
}
#[repr(C)]
#[derive(Default)]
struct Paint {
    dc:Handle,erase:i32,rect:Rect,restore:i32,update:i32,reserved:[u8;32],
}
#[repr(C)]
#[derive(Default)]
struct Message {
    hwnd:Hwnd,message:u32,wparam:usize,lparam:isize,time:u32,point_x:i32,point_y:i32,private:u32,
}
#[link(name="user32")]
extern "system" {
    fn SetThreadDesktop(desktop:Handle)->i32;
    fn GetThreadDesktop(thread_id:u32)->Handle;
    fn RegisterClassW(spec:*const WndClass)->u16;
    fn UnregisterClassW(name:*const u16,instance:Handle)->i32;
    fn CreateWindowExW(exstyle:u32,class:*const u16,title:*const u16,style:u32,
        x:i32,y:i32,w:i32,h:i32,parent:Hwnd,menu:Handle,instance:Handle,param:*mut c_void)->Hwnd;
    fn DestroyWindow(hwnd:Hwnd)->i32;
    fn BeginPaint(hwnd:Hwnd,paint:*mut Paint)->Handle;
    fn EndPaint(hwnd:Hwnd,paint:*const Paint)->i32;
    fn GetClientRect(hwnd:Hwnd,rect:*mut Rect)->i32;
    fn SetTextColor(dc:Handle,color:u32)->u32;
    fn SetBkMode(dc:Handle,mode:i32)->i32;
    fn DrawTextW(dc:Handle,text:*const u16,count:i32,rect:*mut Rect,format:u32)->i32;
    fn PeekMessageW(message:*mut Message,window:Hwnd,min:u32,max:u32,flags:u32)->i32;
    fn TranslateMessage(message:*const Message)->i32;
    fn DispatchMessageW(message:*const Message)->isize;
    fn InvalidateRect(hwnd:Hwnd,rect:*const Rect,erase:i32)->i32;
    fn UpdateWindow(hwnd:Hwnd)->i32;
}
#[link(name="gdi32")]
extern "system" {
    fn CreateSolidBrush(color:u32)->Handle;
    fn DeleteObject(object:Handle)->i32;
}
#[link(name="kernel32")]
extern "system" { fn GetModuleHandleW(name:*const u16)->Handle; }

unsafe extern "system" fn hud_proc(hwnd:Hwnd,msg:u32,wp:usize,lp:isize)->isize {
    if msg==WM_PAINT {
        let mut paint=Paint::default();
        let dc=unsafe {BeginPaint(hwnd,&mut paint)};
        if dc!=0 {
            let mut rect=Rect::default();
            if unsafe {GetClientRect(hwnd,&mut rect)} != 0 {
                let title:Vec<u16>="AGENT BRIDGE  |  SELECTED WORK DESKTOP".encode_utf16().collect();
                unsafe {
                    SetBkMode(dc,TRANSPARENT);
                    SetTextColor(dc,0x00ff_ffff);
                    DrawTextW(dc,title.as_ptr(),title.len() as i32,&mut rect,
                        DT_CENTER|DT_VCENTER|DT_SINGLELINE);
                }
            }
            unsafe {EndPaint(hwnd,&paint);}
        }
        return 0;
    }
    // No input/command handling: never claim focus or forward keystrokes.
    unsafe {DefWindowProcW(hwnd,msg,wp,lp)}
}
#[link(name="user32")]
extern "system" { fn DefWindowProcW(hwnd:Hwnd,msg:u32,wp:usize,lp:isize)->isize; }

pub(super) struct SafetyHud {
    hwnd:Hwnd,
    class:Vec<u16>,
    instance:Handle,
    brush:Handle,
    last_pulse:Instant,
}
impl SafetyHud {
    pub(super) fn create(desktop:Handle,spec:&DedicatedWindow)->io::Result<Self> {
        // Only a newly spawned, windowless worker thread calls SetThreadDesktop.
        if unsafe {SetThreadDesktop(desktop)}==0
            || require_desktop_name(unsafe{GetThreadDesktop(GetCurrentThreadId())},
                &spec.desktop_name).is_err()
        {return Err(denied());}
        let instance=unsafe {GetModuleHandleW(ptr::null())};
        if instance==0 {return Err(denied());}
        let name=format!("ABSafetyHud_{}_{}",std::process::id(),unsafe{GetCurrentThreadId()});
        let class:Vec<u16>=name.encode_utf16().chain(std::iter::once(0)).collect();
        // RGB(0, 93, 201) -> COLORREF BBGGRR, unmistakable safety blue.
        let brush=unsafe {CreateSolidBrush(0x00c9_5d00)};
        if brush==0 {return Err(denied());}
        let spec=WndClass {
            style:0,callback:Some(hud_proc),extra_class:0,extra_window:0,
            instance,icon:0,cursor:0,background:brush,menu:ptr::null(),
            name:class.as_ptr(),
        };
        if unsafe {RegisterClassW(&spec)}==0 {
            unsafe {DeleteObject(brush);}
            return Err(denied());
        }
        let title:Vec<u16>="Agent Bridge blue safety HUD".encode_utf16()
            .chain(std::iter::once(0)).collect();
        let hwnd=unsafe {CreateWindowExW(
            WS_EX_TOPMOST|WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE|WS_EX_TRANSPARENT,
            class.as_ptr(),title.as_ptr(),WS_POPUP|WS_VISIBLE,
            16,16,330,38,0,0,instance,ptr::null_mut(),
        )};
        if hwnd==0 {
            unsafe {UnregisterClassW(class.as_ptr(),instance);DeleteObject(brush);}
            return Err(denied());
        }
        let mut hud=Self{hwnd,class,instance,brush,last_pulse:Instant::now()};
        if hud.pulse().is_err() {return Err(denied());}
        Ok(hud)
    }
    pub(super) fn pulse(&mut self)->io::Result<()> {
        if unsafe {IsWindow(self.hwnd)}==0 {return Err(denied());}
        let mut message=Message::default();
        // The HUD only pumps messages sent to its own HWND, not unrelated UI.
        for _ in 0..16 {
            if unsafe {PeekMessageW(&mut message,self.hwnd,0,0,PM_REMOVE)}==0 {break;}
            unsafe {TranslateMessage(&message);DispatchMessageW(&message);}
        }
        if unsafe {InvalidateRect(self.hwnd,ptr::null(),0)}==0
            || unsafe {UpdateWindow(self.hwnd)}==0 {return Err(denied());}
        self.last_pulse=Instant::now();
        Ok(())
    }
    pub(super) fn verify(&self)->io::Result<()> {
        if self.last_pulse.elapsed()>Duration::from_secs(2)
            || unsafe {IsWindow(self.hwnd)}==0 {return Err(denied());}
        Ok(())
    }
}
impl Drop for SafetyHud {
    fn drop(&mut self) {
        if self.hwnd!=0 {unsafe {DestroyWindow(self.hwnd);}}
        unsafe {UnregisterClassW(self.class.as_ptr(),self.instance);}
        if self.brush!=0 {unsafe {DeleteObject(self.brush);}}
    }
}