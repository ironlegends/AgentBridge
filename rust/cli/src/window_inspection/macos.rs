//! macOS: retained Accessibility objects and native TCC; AppleScript is used
//! only for the local consent dialog. Target text is argv, never script source.
use super::*;
use std::collections::VecDeque;
use std::ffi::{c_void,CStr};
use std::fs;
use std::mem::{size_of,MaybeUninit};
use std::os::unix::fs::{MetadataExt,OpenOptionsExt};
use std::process::{Command,Stdio};
use std::ptr;

type CFRef=*const c_void;
type CFIndex=isize;
const UTF8:u32=0x08000100;

#[link(name="CoreFoundation",kind="framework")]
extern "C" {
    fn CFRetain(value:CFRef)->CFRef;
    fn CFRelease(value:CFRef);
    fn CFEqual(a:CFRef,b:CFRef)->u8;
    fn CFGetTypeID(value:CFRef)->usize;
    fn CFStringGetTypeID()->usize;
    fn CFArrayGetTypeID()->usize;
    fn CFDictionaryGetTypeID()->usize;
    fn CFBooleanGetTypeID()->usize;
    fn CFStringCreateWithBytes(allocator:CFRef,bytes:*const u8,length:CFIndex,encoding:u32,external:u8)->CFRef;
    fn CFStringGetLength(value:CFRef)->CFIndex;
    fn CFStringGetCString(value:CFRef,buffer:*mut i8,size:CFIndex,encoding:u32)->u8;
    fn CFArrayGetCount(value:CFRef)->CFIndex;
    fn CFArrayGetValueAtIndex(value:CFRef,index:CFIndex)->CFRef;
    fn CFBooleanGetValue(value:CFRef)->u8;
    fn CFDataCreate(allocator:CFRef,bytes:*const u8,length:CFIndex)->CFRef;
    fn CFPropertyListCreateWithData(allocator:CFRef,data:CFRef,options:usize,format:*mut isize,error:*mut CFRef)->CFRef;
    fn CFDictionaryGetValue(dictionary:CFRef,key:CFRef)->CFRef;
}
#[link(name="ApplicationServices",kind="framework")]
extern "C" {
    fn AXIsProcessTrusted()->u8;
    fn AXUIElementCreateSystemWide()->CFRef;
    fn AXUIElementGetTypeID()->usize;
    fn AXUIElementCopyAttributeValue(element:CFRef,attribute:CFRef,value:*mut CFRef)->i32;
    fn AXUIElementCopyAttributeValues(element:CFRef,attribute:CFRef,index:CFIndex,maximum:CFIndex,value:*mut CFRef)->i32;
    fn AXUIElementGetAttributeValueCount(element:CFRef,attribute:CFRef,count:*mut CFIndex)->i32;
    fn AXUIElementGetPid(element:CFRef,pid:*mut i32)->i32;
    fn AXUIElementSetMessagingTimeout(element:CFRef,timeout:f32)->i32;
    fn AXUIElementCopyActionNames(element:CFRef,names:*mut CFRef)->i32;
    fn AXUIElementIsAttributeSettable(element:CFRef,attribute:CFRef,settable:*mut u8)->i32;
    fn AXUIElementPerformAction(element:CFRef,action:CFRef)->i32;
    fn AXUIElementSetAttributeValue(element:CFRef,attribute:CFRef,value:CFRef)->i32;
    fn AXValueGetTypeID()->usize;
    fn AXValueGetType(value:CFRef)->i32;
    fn AXValueGetValue(value:CFRef,kind:i32,data:*mut c_void)->u8;
}

struct Owned(CFRef);
// CF objects are owned/retained and all access is serialized by Session's
// mutex. No AppKit view or run-loop object crosses threads.
unsafe impl Send for Owned {}
impl Owned {
    fn take(value:CFRef)->io::Result<Self>{
        if value.is_null(){Err(error("WINDOW_MACOS_OBJECT_UNAVAILABLE"))}else{Ok(Self(value))}
    }
    fn retain(value:CFRef)->io::Result<Self>{
        if value.is_null(){return Err(error("WINDOW_MACOS_OBJECT_UNAVAILABLE"));}
        Self::take(unsafe{CFRetain(value)})
    }
}
impl Clone for Owned {fn clone(&self)->Self{Self(unsafe{CFRetain(self.0)})}}
impl Drop for Owned {fn drop(&mut self){unsafe{CFRelease(self.0)}}}
fn text(value:&str)->io::Result<Owned>{
    Owned::take(unsafe{CFStringCreateWithBytes(ptr::null(),value.as_ptr(),value.len() as isize,UTF8,0)})
}
fn string_value(value:CFRef,limit:usize)->io::Result<String>{
    if value.is_null()||unsafe{CFGetTypeID(value)!=CFStringGetTypeID()}
        || unsafe{CFStringGetLength(value)}<0||unsafe{CFStringGetLength(value)} as usize>limit
    {return Err(error("WINDOW_MACOS_ATTRIBUTE_UNAVAILABLE"));}
    let mut bytes=vec![0u8;limit.saturating_mul(4)+1];
    if unsafe{CFStringGetCString(value,bytes.as_mut_ptr().cast(),bytes.len() as isize,UTF8)}==0 {
        return Err(error("WINDOW_MACOS_ATTRIBUTE_UNAVAILABLE"));
    }
    let length=bytes.iter().position(|byte|*byte==0).ok_or_else(invalid)?;
    String::from_utf8(bytes[..length].to_vec()).map_err(|_|invalid())
}
fn attr(element:&Owned,name:&str)->io::Result<Owned>{
    require_element(element)?;
    let name=text(name)?;let mut value=ptr::null();
    let status=unsafe{AXUIElementCopyAttributeValue(element.0,name.0,&mut value)};
    if status!=0{return Err(ax_error(status,false));}
    Owned::take(value)
}
fn label(element:&Owned,name:&str,limit:usize)->io::Result<String>{
    let value=attr(element,name)?;string_value(value.0,limit)
}
fn enabled(element:&Owned)->bool{
    attr(element,"AXEnabled").ok().is_some_and(|value|unsafe {
        CFGetTypeID(value.0)==CFBooleanGetTypeID()&&CFBooleanGetValue(value.0)!=0
    })
}
fn ax_error(status:i32,action:bool)->io::Error{
    match status {
        -25211=>error("WINDOW_TCC_ACCESSIBILITY_REQUIRED"),
        -25202=>error("WINDOW_IDENTITY_CHANGED"),
        -25204 if action=>error("WINDOW_ACTION_OUTCOME_UNCERTAIN"),
        -25205|-25206|-25208|-25213=>unsupported(),
        _=>error("WINDOW_MACOS_ACCESSIBILITY_UNAVAILABLE"),
    }
}
fn trusted()->io::Result<()>{
    if unsafe{AXIsProcessTrusted()}==0 {
        Err(error("WINDOW_TCC_ACCESSIBILITY_REQUIRED: grant Accessibility to this local Agent Bridge binary"))
    }else{Ok(())}
}
fn pid(element:&Owned)->io::Result<i32>{
    require_element(element)?;
    let mut pid=0;
    if unsafe{AXUIElementGetPid(element.0,&mut pid)}!=0||pid<=0{return Err(error("WINDOW_PROCESS_UNAVAILABLE"));}
    Ok(pid)
}
#[derive(Clone,PartialEq,Eq)]
struct ProcessIdentity {
    pid:i32,started:(u64,u64),path:PathBuf,device:u64,inode:u64,size:u64,modified:(i64,i64),
}
fn process_identity(pid:i32,selection:&DedicatedWindow)->io::Result<ProcessIdentity>{
    let mut info=MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size=size_of::<libc::proc_bsdinfo>();
    if unsafe{libc::proc_pidinfo(pid,libc::PROC_PIDTBSDINFO,0,info.as_mut_ptr().cast(),size as i32)}!=size as i32 {
        return Err(error("WINDOW_PROCESS_UNAVAILABLE"));
    }
    let info=unsafe{info.assume_init()};
    if info.pbi_pid!=pid as u32||info.pbi_uid!=unsafe{libc::getuid()}
        ||info.pbi_ruid!=unsafe{libc::getuid()}
    {return Err(error("WINDOW_PROCESS_OWNER_MISMATCH"));}
    let mut path=[0u8;4096];
    let count=unsafe{libc::proc_pidpath(pid,path.as_mut_ptr().cast(),path.len() as u32)};
    if count<=0||count as usize>=path.len(){return Err(error("WINDOW_PROCESS_UNAVAILABLE"));}
    let path=unsafe{CStr::from_ptr(path.as_ptr().cast())}.to_str().map_err(|_|invalid())?;
    let actual=fs::canonicalize(path).map_err(|_|error("WINDOW_PROCESS_UNAVAILABLE"))?;
    if actual!=selection.executable||fs::canonicalize(&selection.executable).ok().as_ref()!=Some(&selection.executable){
        return Err(error("WINDOW_EXECUTABLE_MISMATCH"));
    }
    let metadata=fs::metadata(&actual).map_err(|_|error("WINDOW_EXECUTABLE_UNAVAILABLE"))?;
    if !metadata.is_file(){return Err(error("WINDOW_EXECUTABLE_UNAVAILABLE"));}
    Ok(ProcessIdentity {pid,started:(info.pbi_start_tvsec,info.pbi_start_tvusec),
        path:actual,device:metadata.dev(),inode:metadata.ino(),size:metadata.len(),
        modified:(metadata.mtime(),metadata.mtime_nsec())})
}
fn bundle_id(executable:&std::path::Path)->io::Result<String>{
    let macos=executable.parent().ok_or_else(invalid)?;
    let contents=macos.parent().ok_or_else(invalid)?;
    let bundle=contents.parent().ok_or_else(invalid)?;
    if macos.file_name().and_then(|value|value.to_str())!=Some("MacOS")
        ||contents.file_name().and_then(|value|value.to_str())!=Some("Contents")
        ||bundle.extension().and_then(|value|value.to_str())!=Some("app")
    {return Err(error("WINDOW_MACOS_APP_BUNDLE_REQUIRED"));}
    let path=contents.join("Info.plist");
    use std::io::Read;
    // The bundle may be user-writable. A FIFO, link, replacement or growth
    // must not turn an identity check into an unbounded read before consent.
    let file=fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NONBLOCK|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path)
        .map_err(|_|error("WINDOW_MACOS_BUNDLE_UNAVAILABLE"))?;
    let metadata=file.metadata().map_err(|_|error("WINDOW_MACOS_BUNDLE_UNAVAILABLE"))?;
    if !metadata.is_file()||metadata.len()>256*1024{return Err(error("WINDOW_MACOS_BUNDLE_UNAVAILABLE"));}
    let mut bytes=Vec::new();
    file.take(256*1024+1).read_to_end(&mut bytes).map_err(|_|error("WINDOW_MACOS_BUNDLE_UNAVAILABLE"))?;
    if bytes.len()>256*1024{return Err(error("WINDOW_MACOS_BUNDLE_UNAVAILABLE"));}
    let data=Owned::take(unsafe{CFDataCreate(ptr::null(),bytes.as_ptr(),bytes.len() as isize)})?;
    let mut detail=ptr::null();
    let dictionary=unsafe{CFPropertyListCreateWithData(ptr::null(),data.0,0,ptr::null_mut(),&mut detail)};
    if !detail.is_null(){unsafe{CFRelease(detail)};}
    let dictionary=Owned::take(dictionary)?;
    if unsafe{CFGetTypeID(dictionary.0)!=CFDictionaryGetTypeID()}{return Err(error("WINDOW_MACOS_BUNDLE_UNAVAILABLE"));}
    let key=text("CFBundleIdentifier")?;
    string_value(unsafe{CFDictionaryGetValue(dictionary.0,key.0)},256)
}
#[repr(C)]
struct Point{x:f64,y:f64}
#[repr(C)]
struct Size{width:f64,height:f64}
fn geometry(window:&Owned)->io::Result<(i64,i64,u64,u64)>{
    let position=attr(window,"AXPosition")?;let size=attr(window,"AXSize")?;
    if unsafe{CFGetTypeID(position.0)!=AXValueGetTypeID()||CFGetTypeID(size.0)!=AXValueGetTypeID()
        ||AXValueGetType(position.0)!=1||AXValueGetType(size.0)!=2}
    {return Err(error("WINDOW_MACOS_GEOMETRY_UNAVAILABLE"));}
    let mut p=Point{x:0.0,y:0.0};let mut s=Size{width:0.0,height:0.0};
    if unsafe{AXValueGetValue(position.0,1,(&mut p as *mut Point).cast())}==0
        ||unsafe{AXValueGetValue(size.0,2,(&mut s as *mut Size).cast())}==0
        ||![p.x,p.y,s.width,s.height].iter().all(|value|value.is_finite())
        ||p.x.abs()>32768.0||p.y.abs()>32768.0||s.width<=0.0||s.height<=0.0||s.width>8192.0||s.height>8192.0
    {return Err(error("WINDOW_MACOS_GEOMETRY_UNAVAILABLE"));}
    Ok((p.x as i64,p.y as i64,s.width as u64,s.height as u64))
}
fn same(a:&Owned,b:&Owned)->bool{unsafe{CFEqual(a.0,b.0)!=0}}
fn require_element(element:&Owned)->io::Result<()> {
    if unsafe{CFGetTypeID(element.0)!=AXUIElementGetTypeID()}{Err(error("WINDOW_MACOS_ATTRIBUTE_UNAVAILABLE"))}else{Ok(())}
}
fn timeout(element:&Owned)->io::Result<()>{
    require_element(element)?;
    let status=unsafe{AXUIElementSetMessagingTimeout(element.0,2.0)};
    if status!=0{Err(ax_error(status,false))}else{Ok(())}
}

const CONSENT_SCRIPT:&str=r#"on run argv
set targetPath to item 1 of argv
set targetBundle to item 2 of argv
set targetTitle to item 3 of argv
set targetPid to item 4 of argv
set messageText to "Allow Agent Bridge to inspect and use supported controls in this exact foreground window?" & return & return & targetBundle & return & targetPath & return & "Window: " & targetTitle & return & "Process: " & targetPid & return & return & "No other window, global input, or screenshot is authorized."
set answer to display dialog messageText with title "Agent Bridge - Local window consent" buttons {"Deny", "Allow exact window"} default button "Deny" cancel button "Deny" giving up after 60 with icon caution
if gave up of answer then error number -128
if button returned of answer is not "Allow exact window" then error number -128
return "APPROVED"
end run"#;
fn consent_command(selection:&DedicatedWindow,pid:i32)->Command {
    let mut command=Command::new("/usr/bin/osascript");
    command.args(["-l","AppleScript","-e",CONSENT_SCRIPT,"--"])
        .arg(&selection.executable).arg(&selection.class_name).arg(&selection.title).arg(pid.to_string())
        .env_remove("DYLD_INSERT_LIBRARIES").env_remove("DYLD_LIBRARY_PATH").env_remove("DYLD_FRAMEWORK_PATH")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).current_dir("/");
    command
}
fn confirm_dialog(selection:&DedicatedWindow,pid:i32)->io::Result<()>{
    use std::io::Read;
    let mut child=consent_command(selection,pid).spawn().map_err(|_|error("WINDOW_LOCAL_CONSENT_UNAVAILABLE"))?;
    let output=child.stdout.take().ok_or_else(||error("WINDOW_LOCAL_CONSENT_UNAVAILABLE"))?;
    let reader=std::thread::spawn(move||{
        let mut bytes=Vec::new();let _=output.take(128).read_to_end(&mut bytes);bytes
    });
    let deadline=Instant::now()+Duration::from_secs(62);
    let status=loop {
        match child.try_wait() {
            Ok(Some(status))=>break Some(status),
            Ok(None) if Instant::now()<deadline=>std::thread::sleep(Duration::from_millis(50)),
            _=>{let _=child.kill();let _=child.wait();break None;}
        }
    };
    let output=reader.join().map_err(|_|error("WINDOW_LOCAL_CONSENT_UNAVAILABLE"))?;
    if status.is_some_and(|status|status.success())&&output==b"APPROVED\n"{Ok(())}
    else{Err(error("WINDOW_LOCAL_CONSENT_DENIED"))}
}

struct Control {selector:String,element:Owned,role:String,name:String,press:bool,writable:bool}
pub(super) struct Native {
    selection:DedicatedWindow,system:Owned,window:Owned,process:ProcessIdentity,controls:Vec<Control>,
}
impl Native {
    pub(super) fn connect(selection:&DedicatedWindow)->io::Result<Self>{
        if selection.desktop_name!="macos"{return Err(error("WINDOW_PLATFORM_SELECTION_MISMATCH: use macos"));}
        trusted()?;
        let system=Owned::take(unsafe{AXUIElementCreateSystemWide()})?;timeout(&system)?;
        let app=attr(&system,"AXFocusedApplication")?;timeout(&app)?;
        let process=process_identity(pid(&app)?,selection)?;
        if bundle_id(&process.path)?!=selection.class_name{return Err(error("WINDOW_APPLICATION_ID_MISMATCH"));}
        let window=attr(&app,"AXFocusedWindow")?;timeout(&window)?;
        if label(&window,"AXRole",64)?!="AXWindow"||label(&window,"AXTitle",256)?!=selection.title {
            return Err(error("WINDOW_SELECTION_MISMATCH"));
        }
        let mut native=Self{selection:selection.clone(),system,window,process,controls:Vec::new()};
        native.inspect()?;Ok(native)
    }
    fn owns(&self,element:&Owned)->io::Result<()>{
        if unsafe{CFGetTypeID(element.0)!=AXUIElementGetTypeID()}||pid(element)?!=self.process.pid {
            return Err(error("WINDOW_CONTROL_OUT_OF_SCOPE"));
        }
        if same(element,&self.window){return Ok(());}
        let owner=attr(element,"AXWindow")?;
        if !same(&owner,&self.window){return Err(error("WINDOW_CONTROL_OUT_OF_SCOPE"));}
        Ok(())
    }
    fn child_elements(&self,element:&Owned,maximum:usize)->io::Result<Vec<Owned>>{
        let name=text("AXChildren")?;let mut count=0;
        let status=unsafe{AXUIElementGetAttributeValueCount(element.0,name.0,&mut count)};
        if matches!(status,-25205|-25212){return Ok(Vec::new());}
        if status!=0{return Err(ax_error(status,false));}
        if count<=0{return Ok(Vec::new());}
        let mut children=ptr::null();
        let status=unsafe{AXUIElementCopyAttributeValues(element.0,name.0,0,count.min(maximum as isize),&mut children)};
        if status!=0{return Err(ax_error(status,false));}
        let children=Owned::take(children)?;
        if unsafe{CFGetTypeID(children.0)!=CFArrayGetTypeID()}{return Err(error("WINDOW_MACOS_ATTRIBUTE_UNAVAILABLE"));}
        let count=unsafe{CFArrayGetCount(children.0)};
        if count<0||count as usize>maximum{return Err(error("WINDOW_TREE_LIMIT"));}
        (0..count).map(|index|Owned::retain(unsafe{CFArrayGetValueAtIndex(children.0,index)})).collect()
    }
    fn control(&self,element:Owned,index:usize)->io::Result<Option<Control>>{
        self.owns(&element)?;
        let role=label(&element,"AXRole",64)?;
        let subrole=label(&element,"AXSubrole",128).unwrap_or_default();
        let name=label(&element,"AXTitle",512).or_else(|_|label(&element,"AXDescription",512)).unwrap_or_default();
        let sensitive=format!("{role} {subrole} {name}").to_ascii_lowercase();
        if ["secure","password","secret","token","credit","payment","authentication"].iter().any(|word|sensitive.contains(word)){
            return Ok(None);
        }
        let mut names=ptr::null();let mut press=false;
        if unsafe{AXUIElementCopyActionNames(element.0,&mut names)}==0 {
            let names=Owned::take(names)?;
            if unsafe{CFGetTypeID(names.0)==CFArrayGetTypeID()} {
                let count=unsafe{CFArrayGetCount(names.0)}.clamp(0,64);
                press=(0..count).any(|index|string_value(unsafe{CFArrayGetValueAtIndex(names.0,index)},64).ok().as_deref()==Some("AXPress"));
            }
        }
        let attribute=text("AXValue")?;let mut writable=0;
        let can_set=matches!(role.as_str(),"AXTextField"|"AXTextArea")
            &&unsafe{AXUIElementIsAttributeSettable(element.0,attribute.0,&mut writable)}==0&&writable!=0;
        let available=enabled(&element);
        Ok(Some(Control{selector:format!("control:{index}"),element,role,name,press:press&&available,writable:can_set&&available}))
    }
}
impl Backend for Native {
    fn inspect(&mut self)->io::Result<NativeWindow>{
        trusted()?;
        if process_identity(self.process.pid,&self.selection)?!=self.process{return Err(error("WINDOW_PROCESS_CHANGED"));}
        if bundle_id(&self.process.path)?!=self.selection.class_name{return Err(error("WINDOW_APPLICATION_ID_MISMATCH"));}
        let app=attr(&self.system,"AXFocusedApplication")?;
        if pid(&app)?!=self.process.pid{return Err(error("WINDOW_FOREGROUND_REQUIRED"));}
        let focused=attr(&app,"AXFocusedWindow")?;
        if !same(&focused,&self.window)||label(&self.window,"AXTitle",256)?!=self.selection.title {
            return Err(error("WINDOW_IDENTITY_CHANGED"));
        }
        let (x,y,width,height)=geometry(&self.window)?;
        Ok(NativeWindow{identity:format!("macos:{}:{}:{}",self.process.pid,self.process.started.0,self.process.started.1),
            x,y,width,height,enabled:enabled(&self.window)})
    }
    fn confirm(&mut self,selection:&DedicatedWindow)->io::Result<()>{confirm_dialog(selection,self.process.pid)}
    fn capabilities(&self)->Capabilities {
        Capabilities{backend:"macos_accessibility",tree:"macos_accessibility_elements",
            actions:&["wait","invoke","set_value"],screenshot:false}
    }
    fn snapshot(&mut self,options:SnapshotOptions)->io::Result<NativeSnapshot>{
        self.inspect()?;self.controls.clear();
        let mut elements=Vec::new();let mut truncated=false;
        if options.tree {
            let mut queue=VecDeque::from([(self.window.clone(),0usize)]);
            let deadline=Instant::now()+Duration::from_secs(3);let mut inspected=0;
            while let Some((element,depth))=queue.pop_front() {
                if Instant::now()>deadline||inspected>=400||elements.len()>=options.maximum {
                    truncated=true;break;
                }
                inspected+=1;self.owns(&element)?;
                // Sensitive elements exclude their entire subtree; inspecting
                // a secure editor's children must not expose a hidden value.
                let Some(control)=self.control(element.clone(),self.controls.len()+1)? else {continue;};
                if depth<12 {
                    for child in self.child_elements(&element,201)? {
                        if queue.len()>=400{truncated=true;break;}
                        queue.push_back((child,depth+1));
                    }
                }else{truncated=true;}
                if options.interactive&&!control.press&&!control.writable{continue;}
                elements.push(json!({"ref":control.selector,"role":control.role,"name":control.name,
                    "supports_invoke":control.press,"supports_set_value":control.writable}));
                self.controls.push(control);
            }
        }
        self.inspect()?;
        Ok(NativeSnapshot{elements,truncated,screenshot:None,
            screenshot_status:"unsupported_without_verified_native_window_capture"})
    }
    fn action(&mut self,action:&Action)->io::Result<Value>{
        self.inspect()?;
        let selector=match action{Action::Invoke{selector}|Action::SetValue{selector,..}=>selector,_=>return Err(unsupported())};
        let index=self.controls.iter().position(|control|control.selector==*selector).ok_or_else(||error("WINDOW_CONTROL_STALE"))?;
        let observed=&self.controls[index];
        let current=self.control(observed.element.clone(),index+1)?.ok_or_else(||error("WINDOW_CONTROL_STALE"))?;
        if current.role!=observed.role||current.name!=observed.name{return Err(error("WINDOW_CONTROL_STALE"));}
        let status=match action {
            Action::Invoke{..} if observed.press&&current.press=>{
                let action=text("AXPress")?;unsafe{AXUIElementPerformAction(current.element.0,action.0)}
            }
            Action::SetValue{value,..} if observed.writable&&current.writable=>{
                let attribute=text("AXValue")?;let value=text(value)?;
                unsafe{AXUIElementSetAttributeValue(current.element.0,attribute.0,value.0)}
            }
            _=>return Err(unsupported()),
        };
        self.controls.clear();
        if status!=0{return Err(ax_error(status,true));}
        Ok(json!({"completed":true,"transport":"macos_accessibility","effect_verified":false}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn native_fixture(mut command:Command)->std::process::Output {
        let mut child=command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let deadline=Instant::now()+Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_))=>return child.wait_with_output().unwrap(),
                Ok(None) if Instant::now()<deadline=>std::thread::sleep(Duration::from_millis(20)),
                _=>{let _=child.kill();let _=child.wait();panic!("owned AppleScript fixture timed out");}
            }
        }
    }
    #[test]
    fn local_consent_keeps_untrusted_text_out_of_applescript_source(){
        let attack="\" & do shell script \"touch /tmp/not-allowed\" & \"";
        let selection=DedicatedWindow{desktop_name:"macos".into(),executable:PathBuf::from("/Applications/Fixture.app/Contents/MacOS/Fixture"),
            class_name:"test.fixture".into(),title:attack.into()};
        let command=consent_command(&selection,123);
        let args=command.get_args().collect::<Vec<_>>();
        assert_eq!(args[3],CONSENT_SCRIPT);
        assert!(!CONSENT_SCRIPT.contains(attack));
        assert_eq!(args[7],attack);
        assert_eq!(command.get_program(),"/usr/bin/osascript");
    }
    #[test]
    fn native_non_element_values_are_refused_before_accessibility_messages(){
        let value=text("A real CFString is not an AXUIElement").unwrap();
        assert_eq!(pid(&value).unwrap_err().to_string(),"WINDOW_MACOS_ATTRIBUTE_UNAVAILABLE");
        assert_eq!(timeout(&value).unwrap_err().to_string(),"WINDOW_MACOS_ATTRIBUTE_UNAVAILABLE");
        assert!(attr(&value,"AXTitle").is_err());
    }
    #[test]
    fn native_bundle_identity_rejects_fifo_symlink_and_oversized_plist(){
        use std::os::unix::ffi::OsStrExt;
        struct Scratch(PathBuf);
        impl Drop for Scratch {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
        let scratch=Scratch(std::env::temp_dir().join(format!("agent-bridge-bundle-fixture-{}",new_id().unwrap())));
        let executable=scratch.0.join("Fixture.app/Contents/MacOS/Fixture");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        let plist=executable.parent().unwrap().parent().unwrap().join("Info.plist");
        let raw=std::ffi::CString::new(plist.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe{libc::mkfifo(raw.as_ptr(),0o600)},0);
        let selected=executable.clone();let(send,receive)=std::sync::mpsc::channel();
        let reader=std::thread::spawn(move||{let _=send.send(bundle_id(&selected));});
        assert!(receive.recv_timeout(Duration::from_secs(1)).expect("FIFO identity must fail without blocking").is_err());
        reader.join().unwrap();fs::remove_file(&plist).unwrap();
        let other=scratch.0.join("other.plist");fs::write(&other,b"not a real plist").unwrap();
        std::os::unix::fs::symlink(&other,&plist).unwrap();assert!(bundle_id(&executable).is_err());
        fs::remove_file(&plist).unwrap();fs::write(&plist,vec![b'x';256*1024+1]).unwrap();
        assert!(bundle_id(&executable).is_err());
        fs::write(&plist,b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>org.fixture.literal</string></dict></plist>").unwrap();
        assert_eq!(bundle_id(&executable).unwrap(),"org.fixture.literal");
    }
    #[test]
    fn native_applescript_argv_is_literal_and_consent_script_compiles_without_execution(){
        let payload="\" & do shell script \"not-a-command\" & \" - literal Unicode";
        let mut command=Command::new("/usr/bin/osascript");
        command.args(["-l","AppleScript","-e","on run argv\nreturn item 1 of argv\nend run","--",payload]);
        let output=native_fixture(command);
        assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
        assert_eq!(String::from_utf8(output.stdout).unwrap(),format!("{payload}\n"));
        struct Scratch(PathBuf);
        impl Drop for Scratch {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
        let scratch=Scratch(std::env::temp_dir().join(format!("agent-bridge-consent-fixture-{}",new_id().unwrap())));
        fs::create_dir(&scratch.0).unwrap();
        let mut compiler=Command::new("/usr/bin/osacompile");
        compiler.arg("-o").arg(scratch.0.join("consent.scpt")).arg("-e").arg(CONSENT_SCRIPT);
        let output=native_fixture(compiler);
        assert!(output.status.success(),"{}",String::from_utf8_lossy(&output.stderr));
        assert!(scratch.0.join("consent.scpt").is_file());
    }
}
