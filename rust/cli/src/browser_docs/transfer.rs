//! Physically pinned, locally selected project input and create-new output.
//! Windows-only. No Web-provided paths, no reparse/symlink/hardlink traversal.
//! Calls the existing lifecycle project qualification for every directory
//! before a file is opened, and holds no-delete-share handles across Chrome.
#![cfg(windows)]

use agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory;
use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

const REPARSE: u32 = 0x400;
const DIRECTORY: u32 = 0x10;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SHARE_READ: u32 = 0x1;
pub(super) const MAX_INPUT_BYTES: usize = 256 * 1024;
pub(super) const MAX_DOWNLOAD_BYTES: usize = 1024 * 1024;

#[repr(C)]
#[derive(Default)]
struct FileTime { low: u32, high: u32 }
#[repr(C)]
#[derive(Default)]
struct HandleInfo {
    attr: u32,
    created: FileTime,
    accessed: FileTime,
    modified: FileTime,
    volume: u32,
    size_hi: u32,
    size_lo: u32,
    links: u32,
    index_hi: u32,
    index_lo: u32,
}
#[link(name="kernel32")]
extern "system" {
    fn GetFileInformationByHandle(h: *mut c_void, info: *mut HandleInfo) -> i32;
    fn GetFinalPathNameByHandleW(
        h: *mut c_void, output: *mut u16, length: u32, flags: u32,
    ) -> u32;
}
fn refuse() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "BRIDGE_PROJECT_TRANSFER_REFUSED")
}
fn disk_path(path: &Path) -> io::Result<String> {
    let name=path.to_str().ok_or_else(refuse)?;
    if !path.is_absolute() || name.len()>2048 || name.contains('~')
        || name.contains("..") || name.contains(':') && !name.as_bytes().get(1).is_some_and(|b|*b==b':')
    {return Err(refuse());}
    Ok(name.replace('/',"\\"))
}
fn info(file: &File) -> io::Result<HandleInfo> {
    let mut value=HandleInfo::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(),&mut value) }==0
        || value.attr & REPARSE != 0 || value.links!=1
        || value.attr & DIRECTORY!=0
    {return Err(refuse());}
    Ok(value)
}
fn checked_filename(file: &File, expected: &Path) -> io::Result<HandleInfo>{
    let metadata=info(file)?;
    let mut wide=[0u16;4096];
    let count=unsafe { GetFinalPathNameByHandleW(
        file.as_raw_handle(),wide.as_mut_ptr(),wide.len() as u32,0
    ) };
    if count==0||count as usize>=wide.len(){return Err(refuse());}
    let resolved=String::from_utf16(&wide[..count as usize]).map_err(|_|refuse())?;
    let resolved=resolved.strip_prefix(r"\\?\").unwrap_or(&resolved);
    if !resolved.eq_ignore_ascii_case(&disk_path(expected)?) {return Err(refuse());}
    Ok(metadata)
}
pub(super) fn safe_relative_file(input:&str)->bool{
    !input.is_empty()&&input.len()<=300&&input.is_ascii()
        && !input.contains('\\')&&!input.contains(':')&&!input.contains('~')
        && !input.starts_with('/')&&!input.ends_with('/')
        && input.split('/').all(|part|!part.is_empty()&&!part.starts_with('.')
            && !part.ends_with('.')&&!part.ends_with(' ')
            && part.bytes().all(|b|b.is_ascii_alphanumeric()
                || matches!(b,b'.'|b'_'|b'-')))
}
pub(super) fn safe_relative_dir(input:&str)->bool{
    safe_relative_file(&format!("{input}/file.txt"))
        && !input.is_empty() && input.split('/').all(|p|p!="."&&p!="..")
}
pub(super) fn sha(bytes:&[u8])->String {
    format!("{:x}",Sha256::digest(bytes))
}
fn bounded_read(mut file:&File, cap:usize)->io::Result<Vec<u8>>{
    let mut bytes=Vec::new();
    let mut limited=(&mut file).take(cap as u64 + 1);
    limited.read_to_end(&mut bytes).map_err(|_|refuse())?;
    if bytes.is_empty()||bytes.len()>cap {return Err(refuse());}
    Ok(bytes)
}
pub(super) struct ProjectInputPin {
    _folder: PinnedProjectDirectory,
    file: File,
    path: PathBuf,
    pub(super) basename: String,
    pub(super) size: u64,
    pub(super) sha256: String,
    volume: u32,
    file_index: u64,
}
impl ProjectInputPin {
    pub(super) fn open(project:&Path,relative:&str)->io::Result<Self>{
        if !safe_relative_file(relative)
            || !relative.ends_with(".txt") && !relative.ends_with(".md")
        {return Err(refuse());}
        let path=project.join(relative.replace('/',"\\"));
        let parent=path.parent().ok_or_else(refuse)?;
        let folder=PinnedProjectDirectory::open(parent).map_err(|_|refuse())?;
        // File must be readable under the SAME project boundary approved by
        // the existing DesktopFiles facade (caller checks it separately).
        let mut opt=OpenOptions::new();
        opt.read(true).share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let mut file=opt.open(&path).map_err(|_|refuse())?;
        let identity=checked_filename(&file,&path)?;
        let size=file.metadata()?.len();
        if size==0||size>MAX_INPUT_BYTES as u64{return Err(refuse());}
        let mut buffer=Vec::new();
        std::io::Read::by_ref(&mut file).take(MAX_INPUT_BYTES as u64 + 1).read_to_end(&mut buffer)?;
        if buffer.len() as u64!=size {return Err(refuse());}
        file.seek(SeekFrom::Start(0))?;
        let basename=path.file_name().and_then(|v|v.to_str())
            .ok_or_else(refuse)?.to_owned();
        Ok(Self{
            _folder:folder,file,path,basename,
            size,sha256:sha(&buffer),volume:identity.volume,
            file_index:((identity.index_hi as u64)<<32)|identity.index_lo as u64
        })
    }
    pub(super) fn verify(&mut self)->io::Result<PathBuf>{
        let identity=checked_filename(&self.file,&self.path)?;
        let index=((identity.index_hi as u64)<<32)|identity.index_lo as u64;
        if identity.volume!=self.volume || index!=self.file_index
            || self.file.metadata()?.len()!=self.size
        {return Err(refuse());}
        self.file.seek(SeekFrom::Start(0))?;
        let bytes=bounded_read(&self.file,MAX_INPUT_BYTES)?;
        self.file.seek(SeekFrom::Start(0))?;
        if sha(&bytes)!=self.sha256{return Err(refuse());}
        Ok(self.path.clone())
    }
}

pub(super) struct ProjectOutputPin{
    _dir:PinnedProjectDirectory,
    folder:PathBuf,
    pub(super) relative:String,
}
impl ProjectOutputPin{
    pub(super) fn open(project:&Path,relative:&str)->io::Result<Self>{
        if !safe_relative_dir(relative) {return Err(refuse());}
        let folder=project.join(relative.replace('/',"\\"));
        let dir=PinnedProjectDirectory::open(&folder).map_err(|_|refuse())?;
        Ok(Self{_dir:dir,folder,relative:relative.into()})
    }
    pub(super) fn write_new(&self,filename:&str,bytes:&[u8])->io::Result<(String,u64,String)>{
        if bytes.is_empty()||bytes.len()>MAX_DOWNLOAD_BYTES
            || filename.is_empty()||filename.len()>120
            || !filename.starts_with("agent-bridge-download-")
            || !filename.ends_with(".txt")
            || !filename.bytes().all(|b|b.is_ascii_alphanumeric()
                || matches!(b,b'.'|b'-'))
        {return Err(refuse());}
        let path=self.folder.join(filename);
        if fs::symlink_metadata(&path).is_ok(){return Err(refuse());}
        let mut opt=OpenOptions::new();
        opt.create_new(true).write(true).read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let mut file=opt.open(&path).map_err(|_|refuse())?;
        let record=checked_filename(&file,&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        let file_len=file.metadata()?.len();
        if file_len!=bytes.len() as u64{return Err(refuse());}
        drop(file);
        let reopened=OpenOptions::new().read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        let after=checked_filename(&reopened,&path)?;
        if after.volume!=record.volume || after.index_lo!=record.index_lo
            || after.index_hi!=record.index_hi
        {return Err(refuse());}
        let readback=bounded_read(&reopened,MAX_DOWNLOAD_BYTES)?;
        let digest=sha(&readback);
        if digest!=sha(bytes)||readback.len()!=bytes.len(){return Err(refuse());}
        Ok((format!("{}/{}",self.relative,filename),file_len,digest))
    }
}

pub(super) fn read_private_download(
    root:&Path,guid:&str,max:usize
)->io::Result<Vec<u8>>{
    if guid.len()!=36
        || !guid.bytes().enumerate().all(|(i,b)|
            if matches!(i,8|13|18|23){b==b'-'}
            else{b.is_ascii_hexdigit()})
    {return Err(refuse());}
    let _folder=PinnedProjectDirectory::open(root).map_err(|_|refuse())?;
    let path=root.join(guid);
    let f=OpenOptions::new().read(true).share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path).map_err(|_|refuse())?;
    checked_filename(&f,&path)?;
    if f.metadata()?.len()>max as u64{return Err(refuse());}
    bounded_read(&f,max)
}
