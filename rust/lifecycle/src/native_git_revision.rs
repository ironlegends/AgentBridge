// Copyright 2026 Agent Bridge contributors. Apache-2.0.
//! Native, read-only Windows HEAD resolver for Git's traditional files backend.
//! No git.exe process, shell, object-store read, ref enumeration or fallback.
//! Every Git-file read, path metadata inspection and recheck runs on the
//! impersonated thread using the exact project-specific, Low-IL primary token
//! provided by the existing workspace_access implementation.
//! A returned OID is syntactically valid; object existence is not attested.
//! Refstorage reftable, uncertain Git layouts and concurrent changes refuse.

use super::{
    assert_access, assert_private_denied, identity, normal_local, overlap,
    private_witness, refused, verify_private_same, GitRevisionError,
    PrivateWitness, Result, SHARE_ALL,
};
use crate::workspace_access::{self, PinnedProjectDirectory, PrimaryRestrictedToken};
use std::{
    ffi::OsString,
    fs,
    io::{self, Read},
    os::windows::{
        ffi::OsStringExt, io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
        FILE_SHARE_READ, OPEN_EXISTING,
    },
};

const HEAD_MAX: usize = 512;
const POINTER_MAX: usize = 4096;
const CONFIG_MAX: usize = 64 * 1024;
const PACKED_MAX: usize = 1_048_576;
const MAX_REF: usize = 256;
const MAX_PATH: usize = 4096;
const MAX_FILES: usize = 12;
const MAX_PRIVATE: usize = 32;
const MAX_PARENTS: usize = 12;
const MAX_PINS: usize = 40;
const SHARE_READ_ONLY: u32 = FILE_SHARE_READ; // Deny new write/delete handles

pub const PROVENANCE: &str = "native-git-head-files-v1";

pub struct NativeRevisionSpec<'a> {
    pub workspace: &'a Path,
    pub operator_catalog_file: &'a Path,
    pub database_file: &'a Path,
    pub additional_private_paths: &'a [&'a Path],
}

#[derive(Debug)]
pub struct NativeRevision {
    pub oid: String,
    pub provenance: &'static str,
}

pub struct PreparedNativeRevision {
    _project_pin: PinnedProjectDirectory,
    root: PathBuf,
    protected: Vec<PrivateWitness>,
    primary: PrimaryRestrictedToken,
}

pub fn prepare_native_revision(spec: &NativeRevisionSpec<'_>) -> Result<PreparedNativeRevision> {
    if spec.additional_private_paths.len() > MAX_PRIVATE {
        return Err(refused("Too many private paths in native Git operation"));
    }
    // Physical pin is the established operator-side workspace qualification.
    // No Git repository file or ref is read before impersonation.
    let root = normal_local(spec.workspace, true)?;
    let pin = PinnedProjectDirectory::open(&root)
        .map_err(|e| GitRevisionError::Os{stage:"NATIVE_PIN",error:e})?;
    let mut protected = vec![
        private_witness(spec.operator_catalog_file,true)?,
        private_witness(spec.database_file,true)?,
    ];
    for path in spec.additional_private_paths {
        protected.push(private_witness(path,false)?);
    }
    for item in &protected {
        if overlap(&root,&item.path)? {
            return Err(refused("Native repository overlaps a private operator path"));
        }
    }
    let primary = workspace_access::primary_restricted_token(&pin)
        .map_err(|e| GitRevisionError::Os{stage:"NATIVE_TOKEN",error:e})?;
    let root_id = super::open_path(&root,FILE_READ_ATTRIBUTES,true,SHARE_ALL)
        .and_then(|handle|identity(handle.raw()))?;
    let private_checks = protected.iter()
        .map(|p|(p.path.clone(),p.kind,p.id)).collect::<Vec<_>>();
    let root_check = root.clone();
    workspace_access::probe_with_primary_token(&primary,move||{
        for (path,kind,id) in private_checks {
            assert_private_denied(&PrivateWitness{path,kind,id})?;
        }
        assert_access(
            &root_check,
            windows_sys::Win32::Storage::FileSystem::FILE_LIST_DIRECTORY |
                windows_sys::Win32::Storage::FileSystem::FILE_TRAVERSE |
                FILE_READ_ATTRIBUTES,
            true,root_id,
        )
    }).map_err(|e|GitRevisionError::Os{stage:"NATIVE_ACCESS",error:e})?;
    for item in &protected {verify_private_same(item)?;}
    Ok(PreparedNativeRevision{_project_pin:pin,root,protected,primary})
}

impl PreparedNativeRevision {
    /// Call only after consuming the existing exact-argv command policy permit.
    /// All Git metadata reads occur inside one restricted-token impersonation.
    pub fn resolve(self)->Result<NativeRevision>{
        let Self{_project_pin,root,protected,primary}=self;
        for item in &protected {verify_private_same(item)?;}
        let private_paths=protected.iter().map(|p|p.path.clone()).collect::<Vec<_>>();
        let result=workspace_access::probe_with_primary_token(&primary,move||{
            let mut reader=Reader::new(private_paths);
            let oid=reader.resolve(&root)?;
            reader.recheck()?;
            Ok(oid)
        }).map_err(|e|GitRevisionError::Os{stage:"NATIVE_GIT_REF",error:e})?;
        for item in &protected {verify_private_same(item)?;}
        Ok(NativeRevision{oid:result,provenance:PROVENANCE})
    }
}

fn invalid(s:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidData,s)}
fn unsupported(s:&'static str)->io::Error{io::Error::new(io::ErrorKind::Unsupported,s)}

fn valid_segment(s:&str)->bool{
    if s.is_empty() || s=="." || s==".." || s.ends_with('.') || s.ends_with(' ')
        || s.len()>255 || s.chars().any(|c|c.is_control()||"<>:\"/\\|?*".contains(c))
    {return false;}
    let stem=s.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(stem.as_str(),"CON"|"PRN"|"AUX"|"NUL"|"CONIN$"|"CONOUT$"){return false;}
    !(stem.len()==4 && (stem.starts_with("COM")||stem.starts_with("LPT"))
      && matches!(stem.as_bytes()[3],b'1'..=b'9'))
}
fn local_absolute(p:&Path)->io::Result<()>{
    let text=p.to_str().ok_or_else(||invalid("non-Unicode Git path"))?;
    if !p.is_absolute() || text.len()>MAX_PATH{return Err(invalid("Git path must be absolute and bounded"));}
    let mut disk=false;
    let mut root=false;
    let mut count=0usize;
    for part in p.components(){
        match part{
            Component::Prefix(prefix)=>match prefix.kind(){
                Prefix::Disk(_)=>disk=true,
                _=>return Err(invalid("network or device Git path refused")),
            },
            Component::RootDir=>root=true,
            Component::Normal(name)=>{
                if !valid_segment(name.to_str().ok_or_else(||invalid("non-Unicode path component"))?){
                    return Err(invalid("invalid Git path component"));
                }
                count+=1;
            },
            _=>return Err(invalid("non-normal Git path component")),
        }
    }
    if !disk || !root || count==0{return Err(invalid("Git path cannot be a volume root"));}
    Ok(())
}
fn resolved_pointer(base:&Path,raw:&str)->io::Result<PathBuf>{
    if raw.is_empty() || raw.len()>MAX_PATH || raw.contains('\0'){return Err(invalid("invalid Git directory pointer"));}
    let value=raw.replace('/',"\\");
    if value.starts_with("\\\\"){return Err(invalid("network/device Git pointer refused"));}
    let path=Path::new(&value);
    let combined=if path.is_absolute(){path.to_owned()}
        else if matches!(path.components().next(),Some(Component::Prefix(_))){
            return Err(invalid("drive-relative Git pointer refused"));
        }else{base.join(path)};
    let mut output=PathBuf::new();
    let mut parents=0;
    for part in combined.components(){
        match part{
            Component::Prefix(prefix)=>match prefix.kind(){
                Prefix::Disk(_)=>output.push(prefix.as_os_str()),
                _=>return Err(invalid("device/network Git pointer refused")),
            },
            Component::RootDir=>output.push(part.as_os_str()),
            Component::CurDir=>{},
            Component::ParentDir=>{
                parents+=1;
                if parents>MAX_PARENTS || !output.pop() || !output.is_absolute(){
                    return Err(invalid("Git pointer escapes local volume"));
                }
            },
            Component::Normal(seg)=>{
                if !valid_segment(seg.to_str().ok_or_else(||invalid("non-Unicode Git pointer"))?){
                    return Err(invalid("unsafe Git directory pointer"));
                }
                output.push(seg);
            },
        }
    }
    local_absolute(&output)?;
    Ok(output)
}
fn valid_ref(r:&str)->io::Result<()>{
    let Some(rest)=r.strip_prefix("refs/heads/") else{
        return Err(invalid("HEAD ref outside supported refs/heads namespace"));
    };
    if r.len()>MAX_REF || rest.is_empty() || r.contains("..")||r.contains("@{")
        || rest.ends_with('/') || rest.split('/').count()>16 {
        return Err(invalid("invalid Git reference structure"));
    }
    for seg in rest.split('/'){
        if !valid_segment(seg)||seg.starts_with('.')||seg.ends_with(".lock")
            || !seg.bytes().all(|c|c.is_ascii_alphanumeric()||
                matches!(c,b'-'|b'_'|b'.'|b'+')){
            return Err(invalid("unsupported Git reference name"));
        }
    }
    Ok(())
}
fn parse_oid(raw:&str,digits:usize)->io::Result<String>{
    if raw.len()!=digits || !raw.bytes().all(|b|b.is_ascii_hexdigit())
        || raw.bytes().all(|b|b==b'0'){
        return Err(invalid("invalid Git object ID"));
    }
    Ok(raw.to_ascii_lowercase())
}
fn text(bytes:&[u8],maximum:usize)->io::Result<&str>{
    if bytes.len()>maximum || bytes.contains(&0){
        return Err(invalid("Git metadata size/encoding invalid"));
    }
    std::str::from_utf8(bytes).map_err(|_|invalid("Git metadata must be UTF-8"))
}
fn single_line(bytes:&[u8],limit:usize)->io::Result<&str>{
    let line=text(bytes,limit)?;
    let line=line.strip_suffix("\r\n").or_else(||line.strip_suffix('\n')).unwrap_or(line);
    if line.is_empty()||line.contains('\r')||line.contains('\n'){return Err(invalid("invalid Git line"));}
    Ok(line)
}

// Every metadata inspection is performed on the restricted-token worker.
// Pins are owned by Reader and outlive its final recheck, not just one read.
// Keep a read handle for each present Git metadata file as well; its sharing
// excludes new write/delete handles. We still verify both ID and bytes twice.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
struct Stamp {
    volume: u32,
    index: u64,
    links: u32,
    bytes: u64,
    mtime: (u32,u32),
    directory: bool,
}
fn stamp(md:&BY_HANDLE_FILE_INFORMATION)->io::Result<Stamp>{
    if md.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid("reparse Git metadata entry refused"));
    }
    let index=(u64::from(md.nFileIndexHigh)<<32)|u64::from(md.nFileIndexLow);
    if index==0 || md.dwVolumeSerialNumber==0 {
        return Err(invalid("Git metadata file identity unavailable"));
    }
    Ok(Stamp{
        volume:md.dwVolumeSerialNumber,index,links:md.nNumberOfLinks,
        bytes:(u64::from(md.nFileSizeHigh)<<32)|u64::from(md.nFileSizeLow),
        mtime:(md.ftLastWriteTime.dwHighDateTime,md.ftLastWriteTime.dwLowDateTime),
        directory:md.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY!=0,
    })
}
fn file_info(f:&fs::File)->io::Result<BY_HANDLE_FILE_INFORMATION>{
    let mut md:BY_HANDLE_FILE_INFORMATION=unsafe{std::mem::zeroed()};
    if unsafe{GetFileInformationByHandle(f.as_raw_handle().cast(),&mut md)}==0{
        return Err(io::Error::last_os_error());
    }
    Ok(md)
}
fn final_path(file:&fs::File)->io::Result<PathBuf>{
    let mut w=vec![0u16;32768];
    let n=unsafe{GetFinalPathNameByHandleW(file.as_raw_handle().cast(),
        w.as_mut_ptr(),w.len() as u32,0)}as usize;
    if n==0||n>=w.len(){return Err(invalid("Cannot resolve opened Git metadata handle"));}
    Ok(PathBuf::from(OsString::from_wide(&w[..n])))
}
fn file_error(path:&Path,error:io::Error)->io::Error{
    let denied=error.kind()==io::ErrorKind::PermissionDenied ||
        error.raw_os_error()==Some(5);
    if denied {
        io::Error::new(io::ErrorKind::PermissionDenied,
            format!("RESTRICTED_GIT_ACCESS_DENIED: {} (Win32 {:?}): {error}",
                path.display(),error.raw_os_error()))
    } else {
        io::Error::new(error.kind(),
            format!("Git metadata {}: {error}",path.display()))
    }
}
fn from_win_file(path:&Path,access:u32,dir:bool)->io::Result<Option<fs::File>>{
    local_absolute(path)?;
    let wide=super::wide(path.as_os_str())
        .map_err(|_|invalid("Invalid Git metadata path"))?;
    let raw=unsafe{CreateFileW(wide.as_ptr(),access,SHARE_READ_ONLY,
        ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|
        if dir {FILE_FLAG_BACKUP_SEMANTICS}else{0},
        ptr::null_mut())};
    if raw.is_null() || raw==INVALID_HANDLE_VALUE {
        let error=io::Error::last_os_error();
        // Treat as absent ONLY explicit Win32 FILE_NOT_FOUND/PATH_NOT_FOUND.
        // ERROR_ACCESS_DENIED and any other/ambiguous status fail closed.
        return if matches!(error.raw_os_error(), Some(2) | Some(3)) {
            Ok(None)
        } else {
            Err(file_error(path,error))
        };
    }
    // SAFETY: valid unique Win32 handle; ownership transferred to File.
    Ok(Some(unsafe{fs::File::from_raw_handle(raw.cast())}))
}
fn checked_stamp(path:&Path,file:&fs::File)->io::Result<Stamp>{
    let id=stamp(&file_info(file)?)?;
    if !super::same_path(path,&final_path(file)?)
        .map_err(|_|invalid("Cannot compare Git handle and path"))?{
        return Err(invalid("Git path differs from its physical opened handle"));
    }
    if !id.directory && id.links!=1 {
        return Err(invalid("Hard-linked Git metadata file refused"));
    }
    Ok(id)
}
struct FileImage{
    bytes:Vec<u8>,
    id:Stamp,
    _pin:fs::File,
}
struct EntryImage{
    id:Stamp,
    _pin:fs::File,
}
// Under the restricted Git reader, pin ONLY the named directory leaf. The
// original project selection remains pinned with the operator's normal
// token by PreparedNativeRevision::_project_pin. The existing recursive
// PinnedProjectDirectory would require access to the volume's ancestors.
struct LeafDirectoryPin {
    path: PathBuf,
    id: Stamp,
    _handle: fs::File, // no FILE_SHARE_DELETE until the complete final recheck
}

fn open_leaf_directory(path: &Path) -> io::Result<Option<LeafDirectoryPin>> {
    local_absolute(path)?;
    // Opens the physical LEAF with FILE_READ_ATTRIBUTES, no delete sharing,
    // FILE_FLAG_OPEN_REPARSE_POINT and FILE_FLAG_BACKUP_SEMANTICS. No
    // separate open, enumeration or access request against its ancestors.
    let Some(handle) = from_win_file(path, FILE_READ_ATTRIBUTES, true)? else {
        return Ok(None);
    };
    // Includes type/reparse, reliable ID and the full canonical DOS path
    // from GetFinalPathNameByHandleW (not merely the final component).
    let id = checked_stamp(path, &handle)?;
    if !id.directory {
        return Err(invalid("Git directory leaf is not a physical directory"));
    }
    Ok(Some(LeafDirectoryPin { path: path.to_owned(), id, _handle: handle }))
}

fn verify_leaf_directory(pin: &LeafDirectoryPin) -> io::Result<()> {
    if checked_stamp(&pin.path, &pin._handle)? != pin.id {
        return Err(invalid("Pinned Git directory identity changed"));
    }
    // The original handle remains open without delete sharing while a
    // second leaf handle proves the full path still resolves to its ID.
    let now = open_leaf_directory(&pin.path)?
        .ok_or_else(|| invalid("Previously pinned Git directory disappeared"))?;
    if now.id != pin.id {
        return Err(invalid("Git directory path resolves to another physical identity"));
    }
    Ok(())
}

fn pin_parent(
    directory: &Path,
    pins: &mut Vec<LeafDirectoryPin>,
    missing: &mut Vec<PathBuf>,
) -> io::Result<bool> {
    local_absolute(directory)?;
    for pin in pins.iter() {
        if super::same_path(&pin.path, directory)
            .map_err(|_| invalid("Cannot compare pinned Git directory paths"))? {
            verify_leaf_directory(pin)?;
            return Ok(true);
        }
    }
    for path in missing.iter() {
        if super::same_path(path, directory)
            .map_err(|_| invalid("Cannot compare missing Git directory paths"))? {
            if open_leaf_directory(directory)?.is_some() {
                return Err(invalid("Previously missing Git directory appeared"));
            }
            return Ok(false);
        }
    }
    if pins.len() + missing.len() >= MAX_PINS {
        return Err(invalid("Git directory pin and absence budget exceeded"));
    }
    match open_leaf_directory(directory)? {
        Some(pin) => {
            pins.push(pin);
            Ok(true)
        }
        None => {
            // Only a true FILE_NOT_FOUND/PATH_NOT_FOUND from opening THIS
            // leaf permits a later packed-refs fallback. Denial/ambiguity
            // is propagated by from_win_file; no ancestor probes or fallback.
            missing.push(directory.to_owned());
            Ok(false)
        }
    }
}
fn read_file(
    path:&Path,maximum:usize,
    pins:&mut Vec<LeafDirectoryPin>,
    missing:&mut Vec<PathBuf>,
)->io::Result<Option<FileImage>>{
    local_absolute(path)?;
    let parent=path.parent().ok_or_else(||invalid("Git metadata file missing parent"))?;
    if !pin_parent(parent,pins,missing)?{return Ok(None);}
    let Some(file)=from_win_file(path,FILE_READ_DATA|FILE_READ_ATTRIBUTES,false)? else{
        return Ok(None);
    };
    let before=checked_stamp(path,&file)?;
    if before.directory{return Err(invalid("Expected Git file, got directory"));}
    if before.bytes>maximum as u64{
        return Err(invalid("Git metadata exceeds read limit"));
    }
    let mut bytes=Vec::with_capacity(before.bytes as usize);
    (&file).take((maximum+1)as u64).read_to_end(&mut bytes)
        .map_err(|e|file_error(path,e))?;
    if bytes.len()>maximum{return Err(invalid("Git metadata grew beyond bound"));}
    let after=checked_stamp(path,&file)?;
    if after!=before || bytes.len()as u64!=before.bytes {
        return Err(invalid("Git file changed during read"));
    }
    Ok(Some(FileImage{bytes,id:before,_pin:file}))
}
fn entry_kind(
    path:&Path,
    pins:&mut Vec<LeafDirectoryPin>,
    missing:&mut Vec<PathBuf>,
)->io::Result<Option<EntryImage>>{
    local_absolute(path)?;
    let parent=path.parent().ok_or_else(||invalid("Git entry has no parent"))?;
    if !pin_parent(parent,pins,missing)?{return Ok(None);}
    // OPEN_REPARSE_POINT: inspect the entry itself without following a link.
    // FILE_FLAG_BACKUP_SEMANTICS permits either files or directories.
    let Some(file)=from_win_file(path,FILE_READ_ATTRIBUTES,true)?else{
        return Ok(None);
    };
    let id=checked_stamp(path,&file)?;
    Ok(Some(EntryImage{id,_pin:file}))
}
// Only standard Git config required for reference-format recognition. Unrelated
// sections, including quoted remote/branch sections, are ignored; include
// directives and unknown ref-format extensions are rejected.
fn object_width(bytes:&[u8])->io::Result<usize>{
    let config=text(bytes,CONFIG_MAX)?;
    let mut section=String::new();
    let mut version=None;
    let mut object="sha1";
    let mut storage="files";
    for line in config.lines(){
        let line=line.trim();
        if line.is_empty()||line.starts_with('#')||line.starts_with(';'){continue;}
        if line.starts_with('['){
            if !line.ends_with(']'){return Err(unsupported("unsupported Git config section syntax"));}
            let inside=line[1..line.len()-1].trim();
            section=inside.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
            if section.is_empty()||section=="include"||section=="includeif"{
                return Err(unsupported("Git include or unknown section not supported"));
            }
            if (section=="extensions"||section=="core")&&inside.contains('"'){
                return Err(unsupported("subsection altering Git format unsupported"));
            }
            continue;
        }
        let (key,value)=line.split_once('=')
            .ok_or_else(||unsupported("implicit Git config values unsupported"))?;
        let key=key.trim().to_ascii_lowercase();
        let val=value.trim();
        if section=="extensions"{
            if val.contains('"')||val.contains('\\')||val.contains(';')||val.contains('#'){
                return Err(unsupported("complex Git extension configuration"));
            }
            match key.as_str(){
                "refstorage"=>storage=val,
                "objectformat"=>object=val,
                "worktreeconfig"|"relativeworktrees"|"partialclone"|"preciousobjects"=>{},
                _=>return Err(unsupported("unknown Git extension")),
            }
        }else if section=="core"&&key=="repositoryformatversion"{
            version=Some(val.parse::<u32>().map_err(|_|unsupported("invalid repository version"))?);
        }else if key=="refstorage"||key=="objectformat"{
            return Err(unsupported("ref format value outside extensions section"));
        }
    }
    if version.is_none()||version.unwrap()>1||!storage.eq_ignore_ascii_case("files"){
        return Err(unsupported("unsupported or reftable Git ref storage"));
    }
    if object.eq_ignore_ascii_case("sha1"){Ok(40)}
    else if object.eq_ignore_ascii_case("sha256")&&version==Some(1){Ok(64)}
    else{Err(unsupported("unknown Git object format"))}
}
fn packed_oid(bytes:&[u8],name:&str,width:usize)->io::Result<String>{
    let src=text(bytes,PACKED_MAX)?;
    let mut found=None;
    for (index,line) in src.lines().enumerate(){
        if index>=20000||line.len()>512{return Err(invalid("packed-refs scan exceeded limit"));}
        let line=line.trim_end_matches('\r');
        if line.is_empty()||line.starts_with('#'){continue;}
        if let Some(t)=line.strip_prefix('^'){
            parse_oid(t,width)?;
            continue;
        }
        let (raw,reference)=line.split_once(' ')
            .ok_or_else(||invalid("malformed packed-refs entry"))?;
        if reference==name {
            let oid=parse_oid(raw,width)?;
            if found.replace(oid).is_some(){return Err(invalid("duplicate packed ref"));}
        }
    }
    found.ok_or_else(||invalid("HEAD ref absent from loose and packed refs"))
}
// A read record owns the original handle until all revalidation completes.
struct ReadRecord {
    path: PathBuf,
    first: Option<FileImage>,
    limit: usize,
}
struct EntryRecord {
    path: PathBuf,
    first: Option<EntryImage>,
}
struct Reader {
    protected: Vec<PathBuf>,
    records: Vec<ReadRecord>,
    entries: Vec<EntryRecord>,
    pins: Vec<LeafDirectoryPin>,
    missing_parents: Vec<PathBuf>,
}
impl Reader {
    fn new(protected:Vec<PathBuf>)->Self{
        Self{protected,records:Vec::new(),entries:Vec::new(),
            pins:Vec::new(),missing_parents:Vec::new()}
    }
    fn authorize(&self,path:&Path)->io::Result<()>{
        for secret in &self.protected {
            if super::overlap(path,secret)
                .map_err(|_|invalid("Cannot compare private Bridge path"))?{
                return Err(invalid("Git metadata path overlaps private operator data"));
            }
        }
        Ok(())
    }
    fn directory(&mut self, path:&Path)->io::Result<()>{
        self.authorize(path)?;
        if !pin_parent(path,&mut self.pins,&mut self.missing_parents)?{
            return Err(invalid("Required Git metadata directory is absent"));
        }
        Ok(())
    }
    fn kind(&mut self,path:&Path)->io::Result<Option<bool>>{
        if self.entries.len()>=MAX_FILES{return Err(invalid("Git entry observation budget exceeded"));}
        self.authorize(path)?;
        let value=entry_kind(path,&mut self.pins,&mut self.missing_parents)
            .map_err(|e|io::Error::new(e.kind(),
                format!("Git metadata entry {}: {e}",path.display())))?;
        let answer=value.as_ref().map(|v|v.id.directory);
        self.entries.push(EntryRecord{path:path.to_owned(),first:value});
        Ok(answer)
    }
    fn optional(&mut self,path:&Path,max:usize)->io::Result<Option<Vec<u8>>>{
        if self.records.len()>=MAX_FILES{return Err(invalid("Git read budget exceeded"));}
        self.authorize(path)?;
        let first=read_file(path,max,&mut self.pins,&mut self.missing_parents)
            .map_err(|e|io::Error::new(e.kind(),
                format!("Required Git metadata {}: {e}",path.display())))?;
        let result=first.as_ref().map(|v|v.bytes.clone());
        self.records.push(ReadRecord{path:path.to_owned(),first,limit:max});
        Ok(result)
    }
    fn required(&mut self,path:&Path,max:usize)->io::Result<Vec<u8>>{
        self.optional(path,max)?.ok_or_else(||{
            io::Error::new(io::ErrorKind::NotFound,
                format!("RESTRICTED_GIT_REQUIRED_FILE_MISSING: {}",path.display()))
        })
    }
    fn compare_gitfile_identity(&self,original:&Path,backlink_target:&Path)->io::Result<()>{
        let first=self.records.iter().find(|record|
            super::same_path(&record.path,original).unwrap_or(false))
            .and_then(|v|v.first.as_ref())
            .ok_or_else(||invalid("Selected Git gitfile lost its read observation"))?;
        let second=self.records.last().and_then(|v|v.first.as_ref())
            .ok_or_else(||invalid("Backlink did not resolve to an accessible Git gitfile"))?;
        if first.id!=second.id || first.bytes!=second.bytes {
            return Err(invalid("Linked-worktree gitdir backlink does not identify selected .git file"));
        }
        if !super::same_path(original,backlink_target)
            .map_err(|_|invalid("Cannot compare linked-worktree backlink path"))?{
            return Err(invalid("Linked-worktree gitdir backlink points to another .git file"));
        }
        Ok(())
    }
    fn resolve(&mut self,workspace:&Path)->io::Result<String>{
        local_absolute(workspace)?;
        self.directory(workspace)?;
        let dotgit=workspace.join(".git");
        self.authorize(&dotgit)?;
        let (gitdir,linked)=match self.kind(&dotgit)?{
            Some(true)=>(dotgit.clone(),false),
            Some(false)=>{
                let raw=self.required(&dotgit,POINTER_MAX)?;
                let record=single_line(&raw,POINTER_MAX)?;
                let dest=record.strip_prefix("gitdir: ")
                    .ok_or_else(||invalid("Invalid linked-worktree .git file header"))?;
                let resolved=resolved_pointer(workspace,dest)?;
                self.authorize(&resolved)?;
                (resolved,true)
            },
            None=>(workspace.to_owned(),false), // bare repository
        };
        // Keep the pinned Git administrative directory to the end of the
        // snapshot recheck and reject link/reparse changes in its path.
        self.directory(&gitdir)?;
        if linked {
            // Linked worktree admin's 'gitdir' MUST point back to this exact
            // selected .git file, by both normal physical path and handle ID.
            // Missing or ACCESS_DENIED on backlink is a hard failure, never a
            // fallback to the user's normal token or the common Git directory.
            let backlink_path=gitdir.join("gitdir");
            let backbytes=self.required(&backlink_path,POINTER_MAX)?;
            let backtext=single_line(&backbytes,POINTER_MAX)?;
            let backtarget=resolved_pointer(&gitdir,backtext)?;
            self.authorize(&backtarget)?;
            let _selected=self.required(&backtarget,POINTER_MAX)?;
            self.compare_gitfile_identity(&dotgit,&backtarget)?;
        }
        let common_path=gitdir.join("commondir");
        let common=match self.optional(&common_path,POINTER_MAX)? {
            Some(v)=>{
                let dest=resolved_pointer(&gitdir,single_line(&v,POINTER_MAX)?)?;
                self.authorize(&dest)?;
                dest
            },
            None if linked=>{
                return Err(unsupported("Linked worktree without commondir is ambiguous"));
            },
            None=>gitdir.clone(),
        };
        self.directory(&common)?;
        // The physical common-dir config is mandatory and must be accessible
        // using the SAME restricted token. If ACL denies it, include the exact
        // filename in the error; never interpret denial as absent/default.
        let config=self.required(&common.join("config"),CONFIG_MAX)?;
        let width=object_width(&config)?;
        if self.kind(&common.join("reftable"))?.is_some(){
            return Err(unsupported("Reftable Git reference store not supported"));
        }
        let headraw=self.required(&gitdir.join("HEAD"),HEAD_MAX)?;
        let head=single_line(&headraw,HEAD_MAX)?.to_owned();
        let revision=if let Some(reference)=head.strip_prefix("ref: ") {
            valid_ref(reference)?;
            let loose=common.join(reference.replace('/',"\\"));
            match self.optional(&loose,HEAD_MAX)? {
                Some(bytes)=>parse_oid(single_line(&bytes,HEAD_MAX)?,width)?,
                None=>{
                    // Only a genuinely absent loose ref or parent is eligible
                    // for packed-refs fallback. Access denied, reparse or
                    // identity uncertainty propagated above as explicit errors.
                    let packed=self.required(&common.join("packed-refs"),PACKED_MAX)?;
                    packed_oid(&packed,reference,width)?
                },
            }
        }else{
            parse_oid(&head,width)?
        };
        Ok(revision)
    }
    fn recheck(&mut self)->io::Result<()>{
        // Keep all leaf-directory and file handles alive until the entire
        // recheck completes. Reopen each item using the same restricted
        // token and recheck every previously absent file/directory.
        let (pins,missing,entries,records)=(&mut self.pins,
            &mut self.missing_parents,&self.entries,&self.records);
        // No directory or file pin is released before the final recheck.
        // Verify every original directory handle and its reopened leaf.
        for pin in pins.iter() {
            verify_leaf_directory(pin)?;
        }
        for directory in missing.iter() {
            if open_leaf_directory(directory)?.is_some() {
                return Err(invalid("Previously absent Git directory appeared"));
            }
        }
        for record in entries {
            let now=entry_kind(&record.path,pins,missing)?;
            match (&record.first,&now){
                (None,None)=>{},
                (Some(before),Some(after))=>{
                    if before.id!=after.id ||
                        checked_stamp(&record.path,&before._pin)?!=before.id{
                        return Err(invalid("Git entry identity changed during resolution"));
                    }
                }
                _=>return Err(invalid("Git entry appeared or disappeared during resolution")),
            }
        }
        for record in records {
            let now=read_file(&record.path,record.limit,pins,missing)?;
            match (&record.first,&now){
                (None,None)=>{},
                (Some(before),Some(after))=>{
                    if before.id!=after.id || before.bytes!=after.bytes ||
                        checked_stamp(&record.path,&before._pin)?!=before.id{
                        return Err(invalid("Git metadata identity or content changed during resolution"));
                    }
                },
                _=>return Err(invalid("Git metadata appeared or disappeared during resolution")),
            }
        }
        // Detect a directory identity change or a newly materialized loose
        // parent even if it happened during the file/entry rechecks above.
        for pin in pins.iter() {
            verify_leaf_directory(pin)?;
        }
        for directory in missing.iter() {
            if open_leaf_directory(directory)?.is_some() {
                return Err(invalid("Previously absent Git directory appeared during recheck"));
            }
        }
        Ok(())
    }
}