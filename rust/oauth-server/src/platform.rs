//! Owner-only paths. No credential paths are inferred from environment variables.
//! The caller supplies a private pre-existing state directory. Never chmod
//! or repair an existing directory, ACL or link automatically.
use std::{
    fs::{self, Metadata, OpenOptions},
    path::{Component, Path, PathBuf},
};
use crate::{OAuthError, Result};

pub(crate) fn root(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.file_name().is_none()
        || path.components().any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(OAuthError::PrivateState("state_directory_not_absolute_canonical"));
    }
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();
        if s.starts_with(r"\\") || s.starts_with("//") {
            return Err(OAuthError::PrivateState("remote_or_device_path_refused"));
        }
    }
    for ancestor in path.ancestors() {
        let md = fs::symlink_metadata(ancestor)?;
        if !md.is_dir() || md.file_type().is_symlink() || reparse(&md) {
            return Err(OAuthError::PrivateState("state_path_alias_or_non_directory"));
        }
    }
    verify_directory(path)?;
    Ok(path.to_path_buf())
}

pub(crate) fn create_requests(path: &Path) -> Result<()> {
    if !path.exists() { create_private_directory(path)?; }
    verify_directory(path)
}

pub(crate) fn verify_directory_for_store(path: &Path) -> Result<()> {
    let md = fs::symlink_metadata(path)?;
    if !md.is_dir() || md.file_type().is_symlink() || reparse(&md) {
        return Err(OAuthError::PrivateState("unsafe_state_directory"));
    }
    verify_directory(path)
}

pub(crate) fn check_file(path: &Path, metadata: &Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() || reparse(metadata) {
        return Err(OAuthError::PrivateState("unsafe_state_file"));
    }
    private_file(path, metadata)
}

pub(crate) fn open_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
}

pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or(OAuthError::PrivateState("missing_parent"))?;
        fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
pub(crate) fn replace_atomically(src: &Path, dst: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::rename(src,dst)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};
        let w = |p:&Path| p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        if unsafe {MoveFileExW(w(src).as_ptr(),w(dst).as_ptr(), MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)} == 0 {
            return Err(OAuthError::PrivateState("atomic_windows_replace_refused"));
        }
    }
    sync_parent(dst)
}
pub(crate) fn publish_new(src: &Path, dst: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::hard_link(src,dst)?;
        fs::remove_file(src)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};
        let w=|p:&Path|p.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        if unsafe{ MoveFileExW(w(src).as_ptr(),w(dst).as_ptr(),MOVEFILE_WRITE_THROUGH) }==0 {
            return Err(OAuthError::PrivateState("atomic_windows_new_file_refused"));
        }
    }
    sync_parent(dst)
}

#[cfg(unix)]
fn reparse(_md:&Metadata)->bool {false}
#[cfg(windows)]
fn reparse(md:&Metadata)->bool {
    use std::os::windows::fs::MetadataExt;
    md.file_attributes() & 0x400 != 0
}

#[cfg(unix)]
fn uid()->Result<u32>{
    let uid=unsafe{libc::getuid()};
    if uid==0 || uid != unsafe{libc::geteuid()} {
        return Err(OAuthError::PrivateState("local_unprivileged_owner_required"));
    }
    Ok(uid)
}
#[cfg(unix)]
fn verify_directory(path:&Path)->Result<()>{
    use std::os::unix::fs::MetadataExt;
    let user=uid()?;
    let own=fs::symlink_metadata(path)?;
    if own.uid()!=user || own.mode()&0o7777!=0o700 || !own.is_dir() {
        return Err(OAuthError::PrivateState("state_directory_must_be_owner_0700"));
    }
    for parent in path.parent().into_iter().flat_map(Path::ancestors){
        let m=fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.file_type().is_symlink()
            || (m.uid()!=user&&m.uid()!=0) || m.mode()&0o022!=0
        {
            return Err(OAuthError::PrivateState("unsafe_state_ancestor"));
        }
    }
    Ok(())
}
#[cfg(unix)]
fn create_private_directory(path:&Path)->Result<()>{
    use std::os::unix::fs::DirBuilderExt;
    let mut b=fs::DirBuilder::new();
    b.mode(0o700).recursive(false);
    b.create(path)?;
    verify_directory(path)
}
#[cfg(unix)]
fn private_file(_path:&Path,md:&Metadata)->Result<()>{
    use std::os::unix::fs::MetadataExt;
    if md.uid()!=uid()? || md.mode()&0o7777!=0o600 || md.nlink()!=1 {
        return Err(OAuthError::PrivateState("state_file_must_be_owner_0600_single_link"));
    }
    Ok(())
}

#[cfg(windows)]
mod windows_acl{
    use super::*;
    use std::{mem::{size_of,zeroed},os::windows::ffi::OsStrExt,ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle,LocalFree},
        Security::{
            GetFileSecurityW,GetTokenInformation,TokenUser,TokenElevation,
            TOKEN_USER,TOKEN_ELEVATION,TOKEN_QUERY,SECURITY_ATTRIBUTES,
            OWNER_SECURITY_INFORMATION,DACL_SECURITY_INFORMATION,
        },
        Security::Authorization::{
            ConvertSidToStringSidW,ConvertStringSecurityDescriptorToSecurityDescriptorW,
            ConvertSecurityDescriptorToStringSecurityDescriptorW,
        },
        Storage::FileSystem::CreateDirectoryW,
        System::Threading::{GetCurrentProcess,OpenProcessToken},
    };
    fn wide(s:&std::ffi::OsStr)->Vec<u16>{ s.encode_wide().chain(Some(0)).collect() }
    unsafe fn string(p:*const u16)->String{
        let mut n=0usize;
        while n<65536 && *p.add(n)!=0 {n+=1;}
        String::from_utf16_lossy(std::slice::from_raw_parts(p,n))
    }
    pub(super) fn sid()->Result<String>{
        let mut token=ptr::null_mut();
        if unsafe{OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut token)}==0 {
            return Err(OAuthError::PrivateState("windows_user_token_unavailable"));
        }
        struct Close(*mut core::ffi::c_void);
        impl Drop for Close{fn drop(&mut self){unsafe{CloseHandle(self.0);}}}
        let _guard=Close(token);
        let mut length=0u32;
        let mut elevated:TOKEN_ELEVATION=unsafe{zeroed()};
        if unsafe{GetTokenInformation(token,TokenElevation,
            (&mut elevated as *mut TOKEN_ELEVATION).cast(),size_of::<TOKEN_ELEVATION>() as u32,
            &mut length)}==0||elevated.TokenIsElevated!=0
        {return Err(OAuthError::PrivateState("elevated_windows_owner_refused"));}
        let mut required=0u32;
        unsafe{GetTokenInformation(token,TokenUser,ptr::null_mut(),0,&mut required);}
        if required==0||required>65536{return Err(OAuthError::PrivateState("windows_sid_unavailable"));}
        let mut data=vec![0usize;(required as usize+size_of::<usize>()-1)/size_of::<usize>()];
        if unsafe{GetTokenInformation(token,TokenUser,data.as_mut_ptr().cast(),required,&mut required)}==0 {
            return Err(OAuthError::PrivateState("windows_sid_unavailable"));
        }
        let sid=unsafe{&*data.as_ptr().cast::<TOKEN_USER>()};
        let mut out=ptr::null_mut();
        if unsafe{ConvertSidToStringSidW(sid.User.Sid,&mut out)}==0{
            return Err(OAuthError::PrivateState("windows_sid_unavailable"));
        }
        let text=unsafe{string(out)};
        unsafe{LocalFree(out.cast());}
        if !text.starts_with("S-1-")||matches!(text.as_str(),"S-1-5-18"|"S-1-5-19"|"S-1-5-20"){
            return Err(OAuthError::PrivateState("service_account_refused"));
        }
        Ok(text)
    }
    fn sddl(path:&Path)->Result<String>{
        let p=wide(path.as_os_str());
        let attrs=OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION;
        let mut size=0u32;
        unsafe{GetFileSecurityW(p.as_ptr(),attrs,ptr::null_mut(),0,&mut size);}
        if size==0||size>65536{return Err(OAuthError::PrivateState("invalid_windows_acl"));}
        let mut bytes=vec![0usize;(size as usize+size_of::<usize>()-1)/size_of::<usize>()];
        if unsafe{GetFileSecurityW(p.as_ptr(),attrs,bytes.as_mut_ptr().cast(),size,&mut size)}==0 {
            return Err(OAuthError::PrivateState("invalid_windows_acl"));
        }
        let mut out=ptr::null_mut();
        if unsafe{ConvertSecurityDescriptorToStringSecurityDescriptorW(
            bytes.as_mut_ptr().cast(),1,attrs,&mut out,ptr::null_mut())}==0{
            return Err(OAuthError::PrivateState("invalid_windows_acl"));
        }
        let value=unsafe{string(out)};
        unsafe{LocalFree(out.cast());}
        Ok(value)
    }
    pub(super) fn verify(path:&Path,dir:bool)->Result<()>{
        let sid=sid()?;
        let value=sddl(path)?;
        let after=value.strip_prefix("O:").ok_or(OAuthError::PrivateState("missing_owner_sid"))?;
        let end=["G:","D:","S:"].iter().filter_map(|x|after.find(x)).min().unwrap_or(after.len());
        if &after[..end]!=sid{return Err(OAuthError::PrivateState("untrusted_file_owner"));}
        let rest=value.split_once("D:").map(|x|x.1)
            .ok_or(OAuthError::PrivateState("missing_private_dacl"))?;
        let acl=rest.split("S:").next().unwrap_or(rest);
        let first=acl.find('(').ok_or(OAuthError::PrivateState("empty_dacl"))?;
        let flags=&acl[..first];
        if dir && !flags.contains('P'){
            return Err(OAuthError::PrivateState("unprotected_state_directory_dacl"));
        }
        if !flags.bytes().all(|c|matches!(c,b'P'|b'A'|b'I'|b'R')){
            return Err(OAuthError::PrivateState("unknown_dacl_control"));
        }
        let mut remain=&acl[first..];let mut owner_allowed=false;
        while !remain.is_empty(){
            if !remain.starts_with('('){return Err(OAuthError::PrivateState("invalid_ace"));}
            let end=remain.find(')').ok_or(OAuthError::PrivateState("invalid_ace"))?;
            let ace:Vec<_>=remain[1..end].split(';').collect();
            if ace.len()!=6||ace[0]!="A"||!matches!(ace[2],"FA"|"0x1f01ff")
                ||!ace[3].is_empty()||!ace[4].is_empty()
                ||(ace[5]!=sid&&ace[5]!="SY")
                ||!ace[1].bytes().all(|c|matches!(c,b'O'|b'C'|b'I'|b'D'))
            {return Err(OAuthError::PrivateState("broad_windows_acl_refused"));}
            if ace[5]==sid{owner_allowed=true;}
            remain=&remain[end+1..];
        }
        if !owner_allowed{return Err(OAuthError::PrivateState("owner_access_missing"));}
        Ok(())
    }
    pub(super) fn create(path:&Path)->Result<()>{
        let sid=sid()?;
        let value=format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)");
        let sddl=wide(std::ffi::OsStr::new(&value));
        let mut descriptor=ptr::null_mut();
        if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),1,&mut descriptor,ptr::null_mut())}==0{
            return Err(OAuthError::PrivateState("private_acl_creation_failed"));
        }
        let attrs=SECURITY_ATTRIBUTES{
            nLength:size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor:descriptor,
            bInheritHandle:0,
        };
        let name=wide(path.as_os_str());
        let created=unsafe{CreateDirectoryW(name.as_ptr(),&attrs)}!=0;
        unsafe{LocalFree(descriptor.cast());}
        if !created{return Err(OAuthError::PrivateState("private_directory_creation_failed"));}
        verify(path,true)
    }
}
#[cfg(windows)]
fn verify_directory(path:&Path)->Result<()>{
    windows_acl::verify(path,true)
}
#[cfg(windows)]
fn create_private_directory(path:&Path)->Result<()>{
    windows_acl::create(path)
}
#[cfg(windows)]
fn private_file(path:&Path,_md:&Metadata)->Result<()>{
    windows_acl::verify(path,false)
}
