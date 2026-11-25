//! Instance-scoped, bounded, single-use file observations and mutations.
//! cap-std directory handles only. Portable locking serializes this instance,
//! not external processes: no global cross-process compare-and-swap is claimed.

use super::*;
use std::io::Write;
use std::collections::{HashMap, VecDeque};

const OBS_TTL: Duration = Duration::from_secs(300);
const MAX_OBS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Identity { volume: u64, number: u128 }

#[derive(Debug)]
struct Snapshot { identity: Identity, data: Vec<u8>, hash: [u8;32] }

impl Snapshot {
    fn new(identity: Identity, data: Vec<u8>) -> Self {
        let mut hash=[0u8;32];
        hash.copy_from_slice(&Sha256::digest(&data));
        Self { identity, data, hash }
    }
}
#[derive(Debug)]
struct Observation { path: String, identity: Identity, hash: [u8;32], len: usize, expires: Instant }
impl Observation {
    fn agrees(&self, snapshot: &Snapshot) -> bool {
        self.identity == snapshot.identity && self.hash == snapshot.hash && self.len == snapshot.data.len()
    }
}

pub(super) struct ObservationStore {
    records: HashMap<String, Observation>,
    order: VecDeque<String>,
}
impl ObservationStore {
    pub(super) fn new() -> Self {
        Self { records: HashMap::new(), order: VecDeque::new() }
    }
    pub(super) fn prune(&mut self) {
        let now = Instant::now();
        while let Some(first) = self.order.front() {
            let expired = self.records.get(first).map_or(true, |v| v.expires <= now);
            if !expired && self.records.len() <= MAX_OBS { break; }
            if let Some(id) = self.order.pop_front() { self.records.remove(&id); }
        }
    }
    fn issue(&mut self, path: String, snapshot: &Snapshot) -> String {
        self.prune();
        while self.records.len() >= MAX_OBS {
            if let Some(id) = self.order.pop_front() { self.records.remove(&id); }
            else { break; }
        }
        let id = Uuid::new_v4().to_string();
        self.records.insert(id.clone(), Observation {
            path, identity: snapshot.identity, hash: snapshot.hash,
            len: snapshot.data.len(), expires: Instant::now() + OBS_TTL,
        });
        self.order.push_back(id.clone());
        id
    }
    fn consume(&mut self, raw: &str, path: &str) -> Result<Observation> {
        let key = Uuid::parse_str(raw)
            .map_err(|_| DesktopError::new("INVALID_OBSERVATION","Observation must be a UUID"))?
            .to_string();
        self.prune();
        let token = self.records.remove(&key)
            .ok_or_else(|| DesktopError::new("OBSERVATION_UNAVAILABLE",
                "Observation unknown, expired, consumed or issued by another instance"))?;
        self.order.retain(|id| id != &key);
        if token.path != path {
            return Err(DesktopError::new("OBSERVATION_PATH_MISMATCH",
                "Observation was issued for another relative path"));
        }
        if token.expires <= Instant::now() {
            return Err(DesktopError::new("OBSERVATION_EXPIRED","Observation expired"));
        }
        Ok(token)
    }
}

fn optional_observation<'a>(a: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    match a.get(key) {
        None => Ok(None),
        Some(Value::String(s)) if s.len() <= 64 && !s.is_empty() => Ok(Some(s)),
        _ => Err(DesktopError::new("INVALID_OBSERVATION","Expected UUID string")),
    }
}
fn required_observation<'a>(a: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    optional_observation(a,key)?.ok_or_else(|| DesktopError::new(
        "OBSERVATION_REQUIRED", format!("{key} must come from a fresh desktop_read_file")))
}
fn stale(why: &str) -> DesktopError { DesktopError::new("STALE_OBSERVATION",why) }
fn uncertain(why: impl Into<String>) -> DesktopError {
    DesktopError::new("UNCERTAIN_RESULT",
        format!("{}; do not retry automatically; inspect both paths first",why.into()))
}
fn check(token: &Observation, current: &Snapshot) -> Result<()> {
    if token.agrees(current) { Ok(()) } else {
        Err(stale("Identity, length, or SHA-256 differs from the consumed observation"))
    }
}

#[cfg(unix)]
pub(super) fn identity(file: &File, links: u64) -> Result<Identity> {
    use cap_std::fs::MetadataExt;
    let md=file.metadata()?;
    if md.nlink()!=links { return Err(DesktopError::new("UNSAFE_HARD_LINK","Unexpected link count")); }
    Ok(Identity { volume:md.dev(),number:u128::from(md.ino()) })
}

#[cfg(windows)]
pub(super) fn identity(file: &File, links: u64) -> Result<Identity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION,FILE_ID_INFO,FileIdInfo,
        GetFileInformationByHandle,GetFileInformationByHandleEx,
    };
    let handle=file.as_raw_handle();
    let mut basic=BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: borrowed live file HANDLE and an ABI-matching, initialized output.
    if unsafe { GetFileInformationByHandle(handle,&mut basic) } == 0 {
        return Err(DesktopError::new("IDENTITY_UNAVAILABLE",io::Error::last_os_error().to_string()));
    }
    if u64::from(basic.nNumberOfLinks)!=links {
        return Err(DesktopError::new("UNSAFE_HARD_LINK","Unexpected link count"));
    }
    let mut extended=FILE_ID_INFO::default();
    // SAFETY: initialized output pointer, exact structure size; handle remains live.
    let success=unsafe { GetFileInformationByHandleEx(handle,FileIdInfo,
        &mut extended as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<FILE_ID_INFO>() as u32) };
    if success!=0 {
        let number=u128::from_le_bytes(extended.FileId.Identifier);
        if number==0 { return Err(DesktopError::new("IDENTITY_UNAVAILABLE","Zero file ID")); }
        return Ok(Identity { volume:extended.VolumeSerialNumber,number });
    }
    let failure=io::Error::last_os_error();
    if !matches!(failure.raw_os_error(),Some(50)|Some(87)) {
        return Err(DesktopError::new("IDENTITY_UNAVAILABLE",failure.to_string()));
    }
    // Conservative legacy fallback for volumes without 128-bit FileIdInfo.
    let n=(u64::from(basic.nFileIndexHigh)<<32)|u64::from(basic.nFileIndexLow);
    if n==0 { return Err(DesktopError::new("IDENTITY_UNAVAILABLE","Zero legacy file index")); }
    Ok(Identity { volume:u64::from(basic.dwVolumeSerialNumber),number:u128::from(n) })
}
#[cfg(not(any(unix,windows)))]
pub(super) fn identity(_file:&File,_links:u64)->Result<Identity>{
    Err(DesktopError::new("UNSUPPORTED_PLATFORM","Windows/Unix only"))
}

#[cfg(unix)]
pub(super) fn dir_identity(dir:&Dir)->Result<Identity>{
    use cap_std::fs::MetadataExt;
    let md=dir.dir_metadata()?;
    ensure_directory(&md)?;
    Ok(Identity { volume:md.dev(),number:u128::from(md.ino()) })
}
#[cfg(windows)]
pub(super) fn dir_identity(dir:&Dir)->Result<Identity>{
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO,FileIdInfo,GetFileInformationByHandleEx,
    };
    let mut value=FILE_ID_INFO::default();
    // SAFETY: borrowed directory HANDLE, initialized output, matching Win32 ABI.
    let ok=unsafe { GetFileInformationByHandleEx(dir.as_raw_handle(),FileIdInfo,
        &mut value as *mut _ as *mut std::ffi::c_void,
        std::mem::size_of::<FILE_ID_INFO>() as u32) };
    if ok==0 { return Err(DesktopError::new("IDENTITY_UNAVAILABLE",
        "Cannot identify parent directory; mutation refused")); }
    let number=u128::from_le_bytes(value.FileId.Identifier);
    if number==0 { return Err(DesktopError::new("IDENTITY_UNAVAILABLE","Zero directory ID")); }
    Ok(Identity { volume:value.VolumeSerialNumber,number })
}
#[cfg(not(any(unix,windows)))]
pub(super) fn dir_identity(_dir:&Dir)->Result<Identity>{
    Err(DesktopError::new("UNSUPPORTED_PLATFORM","Windows/Unix only"))
}

pub(super) fn ensure_single_hard_link(file: &File) -> Result<()> {
    file_kind(&file.metadata()?, 1)?;
    identity(file, 1).map(|_| ())
}

pub(super) fn same_volume(left: &Dir, right: &Dir) -> Result<bool> {
    Ok(dir_identity(left)?.volume == dir_identity(right)?.volume)
}

fn file_kind(md:&Metadata,links:u64)->Result<()> {
    if !md.is_file() || md.is_symlink() || is_reparse(md) {
        return Err(DesktopError::new("UNSAFE_FILE","Linked, reparse, or non-regular file"));
    }
    #[cfg(unix)] {
        use cap_std::fs::MetadataExt;
        if md.nlink()!=links { return Err(DesktopError::new("UNSAFE_HARD_LINK","Unexpected link count")); }
    }
    #[cfg(not(unix))] let _=links;
    Ok(())
}

fn snapshot(parent:&Dir,name:&str,links:u64)->Result<Snapshot>{
    validate_segment(name)?;
    let before=parent.symlink_metadata(name)?;
    file_kind(&before,links)?;
    if before.len()>MAX_FILE_BYTES as u64 {
        return Err(DesktopError::new("FILE_LIMIT_EXCEEDED","File exceeds 1 MiB"));
    }
    let mut options=OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file=parent.open_with(name,&options)?;
    let opened=file.metadata()?;
    file_kind(&opened,links)?;
    if !same_file(&before,&opened) { return Err(stale("File changed during open")); }
    let file_key=identity(&file,links)?;
    let mut data=Vec::new();
    (&mut file).take((MAX_FILE_BYTES+1) as u64).read_to_end(&mut data)?;
    if data.len()>MAX_FILE_BYTES { return Err(DesktopError::new("FILE_LIMIT_EXCEEDED","File grew")); }
    let after=file.metadata()?;
    file_kind(&after,links)?;
    if !same_file(&opened,&after) || after.len()!=data.len() as u64 {
        return Err(stale("File changed during read"));
    }
    let by_path=parent.symlink_metadata(name)?;
    file_kind(&by_path,links)?;
    if !same_file(&after,&by_path) { return Err(stale("Path changed during read")); }
    let verified=parent.open_with(name,&options)?;
    if identity(&verified,links)?!=file_key { return Err(stale("Path identity changed")); }
    if data.contains(&0) || std::str::from_utf8(&data).is_err() {
        return Err(DesktopError::new("TEXT_UTF8_REQUIRED","UTF-8 text without NUL required"));
    }
    Ok(Snapshot::new(file_key,data))
}

/// Read-only helper reused by search; rejects Windows and Unix hard-links.
pub(super) fn verified_contents(parent: &Dir, name: &str) -> Result<Vec<u8>> {
    Ok(snapshot(parent,name,1)?.data)
}

/// Efficient metadata-only file screening for listings and file-info queries.
/// Uses handle identity rather than assuming Windows Metadata exposes nlink.
pub(super) fn verify_regular_entry(parent: &Dir, name: &str) -> Result<()> {
    validate_segment(name)?;
    let before=parent.symlink_metadata(name)?;
    file_kind(&before,1)?;
    let mut options=OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file=parent.open_with(name,&options)?;
    let opened=file.metadata()?;
    file_kind(&opened,1)?;
    if !same_file(&before,&opened) {
        return Err(stale("Entry changed while opening for metadata verification"));
    }
    let _key=identity(&file,1)?;
    Ok(())
}

fn is_absent(parent:&Dir,name:&str)->Result<bool>{
    match parent.symlink_metadata(name) {
        Ok(_)=>Ok(false),
        Err(e) if e.kind()==io::ErrorKind::NotFound=>Ok(true),
        Err(e)=>Err(e.into()),
    }
}

#[cfg(unix)]
fn sync_directory(dir:&Dir)->Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // On Linux, cap-std opens Dir handles with O_PATH, which returns EBADF on
    // fsync(). Reopen "." relative to the pinned Dir handle with O_RDONLY |
    // O_DIRECTORY | O_CLOEXEC so fsync operates on a real directory descriptor.
    let handle = dir.try_clone()?.into_std_file();
    let raw = unsafe {
        libc::openat(
            handle.as_raw_fd(),
            b".\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let real_dir = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) });
    real_dir.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
fn sync_directory(_dir:&Dir)->Result<()> {
    // Windows directory handles do not reliably support FlushFileBuffers.
    Ok(())
}

struct Staged<'a>{ parent:&'a Dir,name:String,armed:bool }
impl<'a> Staged<'a>{
    fn new(parent:&'a Dir,data:&[u8])->Result<Self>{
        if data.len()>MAX_FILE_BYTES { return Err(DesktopError::new("FILE_LIMIT_EXCEEDED","Output too large")); }
        let name=format!("{}{}",TEMP_PREFIX,Uuid::new_v4());
        let mut options=OpenOptions::new();
        options.write(true).create_new(true).follow(FollowSymlinks::No);
        #[cfg(unix)]{
            use cap_std::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file=parent.open_with(&name,&options)?;
        let staged=Self { parent,name,armed:true };
        let result=file.write_all(data).and_then(|()|file.sync_all());
        drop(file);
        result?;
        Ok(staged)
    }
    fn disarm(&mut self){self.armed=false;}
    fn cleanup(&mut self)->Result<()> {
        if self.armed { self.parent.remove_file(&self.name)?;self.disarm(); }
        Ok(())
    }
}
impl Drop for Staged<'_>{
    fn drop(&mut self){if self.armed {let _=self.parent.remove_file(&self.name);}}
}

impl DesktopFiles {
    fn checked_parent(&self,parts:&[String])->Result<(Dir,String,Vec<String>)>{
        self.check_parts(parts)?;
        let (name,ancestors)=parts.split_last().ok_or_else(||DesktopError::new("INVALID_PATH","Path is root"))?;
        Ok((self.open_dir_parts(ancestors)?,name.clone(),ancestors.to_vec()))
    }
    fn check_parent(&self,ancestors:&[String],parent:&Dir)->Result<()>{
        let current=self.open_dir_parts(ancestors)?;
        if dir_identity(&current)?!=dir_identity(parent)? {
            return Err(stale("Parent directory identity changed"));
        }
        Ok(())
    }
    pub(super) fn observed_read(&self,args:&Value,state:&mut ObservationStore)->Result<Value>{
        let a=object(args,&["path","offset","length"])?;
        let parts=relative_parts(required_string(a,"path",MAX_PATH_BYTES)?,false)?;
        let offset=int_in(a,"offset",0,-MAX_SAFE_INTEGER,MAX_SAFE_INTEGER)?;
        let length=int_in(a,"length",1000,1,MAX_LINE_WINDOW as i64)? as usize;
        let (parent,name)=self.parent_and_name(&parts)?;
        let view=snapshot(&parent,&name,1)?;
        let text=std::str::from_utf8(&view.data)
            .map_err(|_|DesktopError::new("TEXT_UTF8_REQUIRED","Invalid UTF-8"))?;
        let lines: Vec<_> = text.lines().collect();
        let total=lines.len();
        let start=if offset<0 {
            total.saturating_sub(usize::try_from(offset.unsigned_abs()).unwrap_or(usize::MAX))
        } else {
            usize::try_from(offset).unwrap_or(usize::MAX).min(total)
        };
        let end=start.saturating_add(length).min(total);
        let path=display_parts(&parts);
        let hash=hex_hash(&view.data);
        let observation_id=state.issue(path.clone(),&view);
        Ok(json!({"path":path,"offset":start,"length":end-start,"total_lines":total,
            "truncated":start!=0 || end!=total,"content":lines[start..end].join("\n"),
            "sha256":hash,"observation_id":observation_id,
            "observation_ttl_seconds":OBS_TTL.as_secs()}))
    }

    pub(super) fn observed_write(&self,args:&Value,state:&mut ObservationStore)->Result<Value>{
        let a=object(args,&["path","content","mode","observation_id"])?;
        let parts=relative_parts(required_string(a,"path",MAX_PATH_BYTES)?,false)?;
        let content=required_string(a,"content",MAX_FILE_BYTES)?;
        if content.contains('\0') {return Err(DesktopError::new("INVALID_TEXT","NUL refused"));}
        let mode=required_string(a,"mode",32)?;
        if mode!="rewrite" && mode!="append" {
            return Err(DesktopError::new("INVALID_ARGUMENT","mode must be rewrite or append"));
        }
        if mode=="append" && !self.workspace_write {
            return Err(DesktopError::new("UNSUPPORTED_MUTATION",
                "Append requires allow_workspace_write"));
        }
        let path=display_parts(&parts);
        let observation=optional_observation(a,"observation_id")?
            .map(|id|state.consume(id,&path)).transpose()?;
        let (parent,name,ancestors)=self.checked_parent(&parts)?;
        if is_absent(&parent,&name)? {
            if observation.is_some() {return Err(stale("Previously observed file disappeared"));}
            let mut stage=Staged::new(&parent,content.as_bytes())?;
            self.check_parent(&ancestors,&parent)?;
            if !is_absent(&parent,&name)? {return Err(stale("Destination appeared"));}
            if let Err(e)=parent.hard_link(&stage.name,&parent,&name) {
                return Err(uncertain(format!("No-clobber create returned an error: {e}")));
            }
            if let Err(e)=stage.cleanup() {
                return Err(uncertain(format!("File created, temp cleanup failed: {e}")));
            }
            if let Err(e)=sync_directory(&parent) {
                return Err(uncertain(format!("File created, directory sync failed: {e}")));
            }
            return Ok(json!({"path":path,"created":true,"mode":mode,"bytes":content.len(),
                "sha256":hex_hash(content.as_bytes()),"publication":"atomic-no-clobber-create"}));
        }
        if !self.workspace_write {
            return Err(DesktopError::new("UNSUPPORTED_MUTATION",
                "Existing-file mutation requires allow_workspace_write"));
        }
        let observed=observation.ok_or_else(||DesktopError::new("OBSERVATION_REQUIRED",
            "Existing file requires a fresh observation_id"))?;
        let before=snapshot(&parent,&name,1)?;
        check(&observed,&before)?;
        let new=if mode=="rewrite" {content.as_bytes().to_vec()} else {
            if before.data.len().saturating_add(content.len())>MAX_FILE_BYTES {
                return Err(DesktopError::new("FILE_LIMIT_EXCEEDED","Append exceeds one MiB"));
            }
            let mut data=before.data;
            data.extend_from_slice(content.as_bytes());
            data
        };
        self.replace_existing(&parent,&name,&ancestors,&observed,&new)?;
        Ok(json!({"path":path,"created":false,"mode":mode,"bytes":new.len(),
            "sha256":hex_hash(&new),"publication":"staged-rename-replace","atomicity":"filesystem-dependent"}))
    }

    pub(super) fn observed_edit(&self,args:&Value,state:&mut ObservationStore)->Result<Value>{
        let a=object(args,&["path","old_string","new_string","expected_replacements","observation_id"])?;
        let parts=relative_parts(required_string(a,"path",MAX_PATH_BYTES)?,false)?;
        let old=required_string(a,"old_string",131_072)?;
        let new=match a.get("new_string") {
            Some(Value::String(value)) => value.as_str(),
            _ => return Err(DesktopError::new("INVALID_ARGUMENT",
                "new_string is a required string (empty is allowed)")),
        };
        if new.len()>131_072 || old.contains('\0') || new.contains('\0'){
            return Err(DesktopError::new("INVALID_TEXT","Unsafe or oversized edit string"));
        }
        let expected=int_in(a,"expected_replacements",1,1,100)? as usize;
        let path=display_parts(&parts);
        let observed=state.consume(required_observation(a,"observation_id")?,&path)?;
        let (parent,name,ancestors)=self.checked_parent(&parts)?;
        let before=snapshot(&parent,&name,1)?;
        check(&observed,&before)?;
        let text=std::str::from_utf8(&before.data)
            .map_err(|_|DesktopError::new("TEXT_UTF8_REQUIRED","Not UTF-8"))?;
        let count=text.matches(old).count();
        if count!=expected {
            return Err(DesktopError::new("REPLACEMENT_COUNT_MISMATCH",
                format!("Expected {expected} replacements, found {count}")));
        }
        let modified=text.replace(old,new);
        if modified.len()>MAX_FILE_BYTES {return Err(DesktopError::new("FILE_LIMIT_EXCEEDED","Edit exceeds one MiB"));}
        self.replace_existing(&parent,&name,&ancestors,&observed,modified.as_bytes())?;
        Ok(json!({"path":path,"replacements":count,"bytes":modified.len(),
            "sha256":hex_hash(modified.as_bytes()),"publication":"staged-rename-replace","atomicity":"filesystem-dependent"}))
    }

    fn replace_existing(&self,parent:&Dir,name:&str,ancestors:&[String],
                        observed:&Observation,new:&[u8])->Result<()> {
        let mut staged=Staged::new(parent,new)?;
        self.check_parent(ancestors,parent)?;
        check(observed,&snapshot(parent,name,1)?)?;
        // A failed rename may have committed: never retry or delete original.
        if let Err(e)=parent.rename(&staged.name,parent,name) {
            return Err(uncertain(format!("Replacement rename failed: {e}")));
        }
        staged.disarm();
        if let Err(e)=sync_directory(parent) {
            return Err(uncertain(format!("Replacement committed, directory sync failed: {e}")));
        }
        let published=snapshot(parent,name,1)
            .map_err(|e|uncertain(format!("Replacement committed, verification failed: {e}")))?;
        if published.data!=new {return Err(uncertain("Published bytes do not match input"));}
        Ok(())
    }

    pub(super) fn observed_move(&self,args:&Value,state:&mut ObservationStore)->Result<Value>{
        self.observed_move_to(self, args, state)
    }

    pub(super) fn observed_move_to(&self,destination_root:&Self,args:&Value,state:&mut ObservationStore)->Result<Value>{
        let a=object(args,&["source","destination","source_observation_id"])?;
        let source=relative_parts(required_string(a,"source",MAX_PATH_BYTES)?,false)?;
        let destination=relative_parts(required_string(a,"destination",MAX_PATH_BYTES)?,false)?;
        if std::ptr::eq(self,destination_root) && source==destination {
            return Err(DesktopError::new("INVALID_ARGUMENT","Same source and destination"));
        }
        let src_path=display_parts(&source);
        let dst_path=display_parts(&destination);
        let observed=state.consume(required_observation(a,"source_observation_id")?,&src_path)?;
        let (from,src,src_ancestors)=self.checked_parent(&source)?;
        let (to,dst,dst_ancestors)=destination_root.checked_parent(&destination)?;
        check(&observed,&snapshot(&from,&src,1)?)?;
        if !is_absent(&to,&dst)? {return Err(DesktopError::new("DESTINATION_EXISTS","Destination must be new"));}
        self.check_parent(&src_ancestors,&from)?;
        destination_root.check_parent(&dst_ancestors,&to)?;
        check(&observed,&snapshot(&from,&src,1)?)?;
        if !is_absent(&to,&dst)? {return Err(DesktopError::new("DESTINATION_EXISTS","Destination appeared"));}
        // Rename may overwrite a new destination. A hard link is no-clobber,
        // but source removal is a SECOND step; no atomic-move claim.
        if let Err(e)=from.hard_link(&src,&to,&dst) {
            return Err(uncertain(format!("No-clobber source link returned an error: {e}")));
        }
        let linked_source=snapshot(&from,&src,2)
            .map_err(|e|uncertain(format!("Destination linked, source recheck failed: {e}")))?;
        let linked_target=snapshot(&to,&dst,2)
            .map_err(|e|uncertain(format!("Destination linked, target recheck failed: {e}")))?;
        check(&observed,&linked_source)
            .map_err(|e|uncertain(format!("Destination linked, source changed: {e}")))?;
        check(&observed,&linked_target)
            .map_err(|e|uncertain(format!("Destination linked, target differs: {e}")))?;
        self.check_parent(&src_ancestors,&from)
            .map_err(|e|uncertain(format!("Destination linked, source parent changed: {e}")))?;
        destination_root.check_parent(&dst_ancestors,&to)
            .map_err(|e|uncertain(format!("Destination linked, target parent changed: {e}")))?;
        from.remove_file(&src)
            .map_err(|e|uncertain(format!("Destination linked, source unlink failed: {e}")))?;
        sync_directory(&from)
            .map_err(|e|uncertain(format!("Source unlinked, source directory sync failed: {e}")))?;
        sync_directory(&to)
            .map_err(|e|uncertain(format!("Source unlinked, destination directory sync failed: {e}")))?;
        if !is_absent(&from,&src)
            .map_err(|e|uncertain(format!("Source removal verification failed: {e}")))? {
            return Err(uncertain("Source name reappeared after removal"));
        }
        let after=snapshot(&to,&dst,1)
            .map_err(|e|uncertain(format!("Source unlinked, destination verify failed: {e}")))?;
        check(&observed,&after)
            .map_err(|e|uncertain(format!("Destination differs after move: {e}")))?;
        Ok(json!({"source":src_path,"destination":dst_path,"moved":true,
            "bytes":after.data.len(),"sha256":hex_hash(&after.data),
            "publication":"no-clobber-link-then-unlink","atomic_move":false}))
    }
}
