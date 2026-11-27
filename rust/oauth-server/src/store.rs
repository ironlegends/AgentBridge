//! Private JSON schema-1 persistence, serialized by a whole-service file lock.
//! Atomic files are renamed over only *this* audience's historical filenames.
use crate::{platform, Audience, CapabilityIdentity, OAuthError, Result};
use crate::model::{Policy, random_token, token_shape, MAX_SAFE_JS_INTEGER};
use agent_bridge_oauth_compat::{HistoricalSnapshot, InspectionPolicy, DiagnosticCode};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
const MAX_DATA:usize=agent_bridge_oauth_compat::MAX_INPUT_BYTES;
const MAX_SMALL:usize=16*1024;

pub(crate) struct Store {
    pub data_file:PathBuf,
    pub requests:PathBuf,
    pub enrollment:PathBuf,
    // A lock is retained for the ENTIRE lifetime of an OAuth service. Other
    // Rust instances and non-cooperating processes must not race mutation.
    // Close the Windows gate before releasing the writer lock.
    #[cfg(windows)]
    _legacy_gate:LegacyGate,
    _lock:File,
    #[cfg(not(windows))]
    _legacy_gate:LegacyGate,
}
struct LegacyGate {
    _handle:File,
    #[cfg(not(windows))]
    file:PathBuf,
    #[cfg(not(windows))]
    nonce:String,
}
impl LegacyGate {
    fn create(path:PathBuf)->Result<Self>{
        let nonce=random_token()?;
        let mut file=open_legacy_gate(&path).map_err(|error|match error {
            OAuthError::Io(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>OAuthError::Busy,
            other=>other,
        })?;
        file.write_all(nonce.as_bytes())?;
        file.sync_all()?;
        Ok(Self{
            _handle:file,
            #[cfg(not(windows))]
            file:path,
            #[cfg(not(windows))]
            nonce,
        })
    }
}
#[cfg(not(windows))]
impl Drop for LegacyGate {
    fn drop(&mut self){
        // Preserve an unexpected replacement rather than delete a foreign
        // historic owner's lock. A crash intentionally retains this marker.
        if read_private(&self.file,MAX_SMALL).ok().flatten()
            .is_some_and(|bytes|bytes==self.nonce.as_bytes())
        {
            let _=fs::remove_file(&self.file);
        }
    }
}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalRequest {
    pub id:String,
    #[serde(rename="clientId")]
    pub client_id:String,
    pub redirect:String,
    pub scope:String,
    pub resource:String,
    pub expires:i64,
    #[serde(rename="bindingHash")]
    pub binding_hash:String,
    pub audience:String,
    #[serde(default, skip_serializing_if = "CapabilityIdentity::is_legacy")]
    pub capability:CapabilityIdentity,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    #[serde(rename="bindingHash")]
    pub binding_hash:String,
    pub expires:i64,
    pub audience:String,
    #[serde(default, skip_serializing_if = "CapabilityIdentity::is_legacy")]
    pub capability:CapabilityIdentity,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment { until:i64 }

impl Store {
    pub fn open(root:&Path,policy:&Policy,now:i64)->Result<(Self,Value)>{
        let root=platform::root(root)?;
        // An old Node sidecar must never run against the same live OAuth state.
        if fs::symlink_metadata(root.join("running.lock")).is_ok(){
            return Err(OAuthError::PrivateState("legacy_oauth_owner_may_be_active"));
        }
        let lock_path=root.join("oauth-rust.lock");
        let file=match open_new(&lock_path) {
            Ok(file)=>file,
            Err(OAuthError::Io(e)) if e.kind()==std::io::ErrorKind::AlreadyExists=>
                open_readwrite(&lock_path)?,
            Err(e)=>return Err(e),
        };
        if let Err(e)=file.try_lock_exclusive(){
            return if e.kind()==std::io::ErrorKind::WouldBlock
                || (cfg!(windows) && e.raw_os_error()==Some(33))
            {Err(OAuthError::Busy)}else{Err(e.into())};
        }
        // Reserve the original Node running.lock name using create_new.
        // A second historic sidecar must refuse to start on the same state.
        let legacy_gate=LegacyGate::create(root.join("running.lock"))?;
        let workstation=policy.audience==Audience::Workstation;
        let data_file=root.join(if workstation{"oauth-workstation.json"}else{"oauth.json"});
        let requests=root.join(if workstation{"requests-workstation"}else{"requests"});
        let enrollment=root.join(if workstation{"enrollment-workstation.json"}else{"enrollment.json"});
        platform::create_requests(&requests)?;
        let data=match read_private(&data_file,MAX_DATA)?{
            Some(bytes)=>{
                let snapshot=HistoricalSnapshot::from_json_bytes(&bytes)
                    .map_err(|_|OAuthError::Incompatible("historical_json_ambiguous_or_oversized"))?;
                let report=snapshot.inspect(InspectionPolicy{
                    audience:policy.audience,resource:&policy.resource,at_epoch_ms:now,
                }).map_err(|_|OAuthError::Incompatible("historical_oauth_policy_invalid"))?;
                if !report.format_compatible||report.diagnostics.iter()
                    .any(|diagnostic|diagnostic.code==DiagnosticCode::RevocationExtensionPresent)
                {
                    return Err(OAuthError::Incompatible("historical_oauth_state_incompatible"));
                }
                snapshot.into_preserved_value()
            }
            None=>if workstation{
                json!({"schema":1,"audience":"workstation","clients":{},"grants":{},"access":{}})
            }else{
                json!({"schema":1,"clients":{},"grants":{},"access":{}})
            },
        };
        Ok((Self{data_file,requests,enrollment,_lock:file,_legacy_gate:legacy_gate},data))
    }

    pub fn bind_manifest(&self,hash:&str,bytes:&[u8])->Result<()> {
        if hash.len()!=64 || !hash.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))
            || bytes.len()>256*1024
        {return Err(OAuthError::Invalid("invalid_unified_manifest_seal"));}
        let parent=self.data_file.parent().ok_or(OAuthError::PrivateState("missing_state_parent"))?;
        let path=parent.join(format!("unified-v1-{hash}.json"));
        match read_private(&path,256*1024)? {
            Some(existing) if existing==bytes=>Ok(()),
            Some(_)=>Err(OAuthError::Incompatible("unified_manifest_seal_changed")),
            None=>atomic_write(&path,bytes,false),
        }
    }

    pub fn save(&self,data:&Value)->Result<()> {
        let bytes=serde_json::to_vec_pretty(data)?;
        if bytes.len()>MAX_DATA{
            return Err(OAuthError::PrivateState("oauth_state_size_limit"));
        }
        atomic_write(&self.data_file,&bytes,true)
    }
    pub fn requested(&self,request:&ApprovalRequest)->Result<()>{
        let path=self.request_file(&request.id)?;
        atomic_write(&path,&serde_json::to_vec(request)?,false)
    }
    pub fn request(&self,id:&str)->Result<Option<ApprovalRequest>>{
        match read_private(&self.request_file(id)?,MAX_SMALL)?{
            Some(bytes)=>Ok(Some(serde_json::from_slice(&bytes).map_err(|_|
                OAuthError::Incompatible("local_request_invalid"))?)),
            None=>Ok(None),
        }
    }
    pub fn approved(&self,id:&str)->Result<Option<Approval>>{
        match read_private(&self.approved_file(id)?,MAX_SMALL)?{
            Some(bytes)=>Ok(Some(serde_json::from_slice(&bytes).map_err(|_|
                OAuthError::Incompatible("local_approval_invalid"))?)),
            None=>Ok(None),
        }
    }

    pub fn remove_request(&self,id:&str)->Result<()>{
        // Only a specific ID generated by this server is ever deleted.
        for file in [self.request_file(id)?,self.approved_file(id)?] {
            match fs::remove_file(file){
                Ok(())=>{},
                Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
                Err(e)=>return Err(e.into()),
            }
        }
        platform::sync_parent(&self.requests)
    }
    pub fn enabled_enrollment(&self,now:i64)->Result<bool>{
        let Some(bytes)=read_private(&self.enrollment,MAX_SMALL)? else{return Ok(false)};
        let e:Enrollment=serde_json::from_slice(&bytes)
            .map_err(|_|OAuthError::Incompatible("enrollment_state_invalid"))?;
        Ok((0..=MAX_SAFE_JS_INTEGER).contains(&e.until) && e.until>now)
    }


    fn request_file(&self,id:&str)->Result<PathBuf>{
        if !token_shape(id){return Err(OAuthError::Invalid("invalid_request_id"))}
        Ok(self.requests.join(format!("{id}.json")))
    }
    fn approved_file(&self,id:&str)->Result<PathBuf>{
        if !token_shape(id){return Err(OAuthError::Invalid("invalid_request_id"))}
        Ok(self.requests.join(format!("{id}.approved")))
    }
}

#[cfg(windows)]
fn open_legacy_gate(path:&Path)->Result<File>{
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{GENERIC_READ,GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_DELETE_ON_CLOSE,FILE_FLAG_OPEN_REPARSE_POINT,
    };
    const DELETE_ACCESS:u32=0x0001_0000;
    let mut options=OpenOptions::new();
    options.read(true).write(true).create_new(true)
        .access_mode(GENERIC_READ|GENERIC_WRITE|DELETE_ACCESS)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_DELETE_ON_CLOSE);
    // The kernel releases this exact file object even when process termination
    // skips Drop. Never apply delete-on-close to a pre-existing owner's marker.
    let file=options.open(path)?;
    platform::check_file(path,&file.metadata()?)?;
    Ok(file)
}
#[cfg(not(windows))]
fn open_legacy_gate(path:&Path)->Result<File>{open_new(path)}

fn open_new(path:&Path)->Result<File>{
    let mut options=OpenOptions::new();
    options.read(true).write(true).create_new(true);
    platform::open_options(&mut options);
    let file=options.open(path)?;
    platform::check_file(path,&file.metadata()?)?;
    Ok(file)
}
fn open_readwrite(path:&Path)->Result<File>{
    let mut options=OpenOptions::new();
    options.read(true).write(true);
    platform::open_options(&mut options);
    let file=options.open(path)?;
    platform::check_file(path,&file.metadata()?)?;
    Ok(file)
}
fn read_private(path:&Path,max:usize)->Result<Option<Vec<u8>>>{
    match fs::symlink_metadata(path){
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),
        Err(e)=>return Err(e.into()),
        Ok(meta)=>platform::check_file(path,&meta)?,
    }
    let mut options=OpenOptions::new();
    options.read(true);
    platform::open_options(&mut options);
    let file=options.open(path)?;
    let md=file.metadata()?;
    platform::check_file(path,&md)?;
    if md.len()>max as u64{return Err(OAuthError::PrivateState("sensitive_state_too_large"));}
    let mut bytes=Vec::new();
    file.take(max as u64+1).read_to_end(&mut bytes)?;
    if bytes.len()>max{return Err(OAuthError::PrivateState("sensitive_state_too_large"));}
    Ok(Some(bytes))
}
fn atomic_write(path:&Path,body:&[u8],replace:bool)->Result<()>{
    if body.len()>MAX_DATA{return Err(OAuthError::PrivateState("sensitive_state_too_large"));}
    if let Ok(md)=fs::symlink_metadata(path){
        platform::check_file(path,&md)?;
        if !replace{return Err(OAuthError::Busy)}
    }
    let parent=path.parent().ok_or(OAuthError::PrivateState("missing_state_parent"))?;
    platform::verify_directory_for_store(parent)?;
    path.file_name().ok_or(OAuthError::PrivateState("missing_file_name"))?;
    // A same-directory random name keeps valid destinations usable near OS path limits.
    let temporary=parent.join(format!(".oauth-{}.tmp",random_token()?));
    let write_result=(||->Result<()>{
        let mut file=open_new(&temporary)?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        if replace{
            // If target appeared during preparation, still refuse an
            // unqualified new file. Only the writer holding the lock mutates.
            if let Ok(md)=fs::symlink_metadata(path){
                platform::check_file(path,&md)?;
            }
            platform::replace_atomically(&temporary,path)
        }else{
            platform::publish_new(&temporary,path)
        }
    })();
    if write_result.is_err(){let _=fs::remove_file(&temporary);}
    write_result
}


/// A separate on-machine operator CLI can inspect/approve request files while
/// the service owns the token-state writer lock. LocalFiles never opens
/// oauth.json, client secrets, or a token database.
pub(crate) struct LocalFiles {
    requests: PathBuf,
    enrollment: PathBuf,
}
impl LocalFiles {
    pub fn open(root:&Path,policy:&Policy)->Result<Self>{
        let root=platform::root(root)?;
        let workstation=policy.audience==Audience::Workstation;
        let requests=root.join(if workstation{"requests-workstation"}else{"requests"});
        let enrollment=root.join(if workstation{"enrollment-workstation.json"}else{"enrollment.json"});
        platform::create_requests(&requests)?;
        Ok(Self{requests,enrollment})
    }
    pub fn request(&self,id:&str)->Result<Option<ApprovalRequest>>{
        if !token_shape(id){return Err(OAuthError::Invalid("invalid_request_id"));}
        let path=self.requests.join(format!("{id}.json"));
        match read_private(&path,MAX_SMALL)?{
            Some(bytes)=>Ok(Some(serde_json::from_slice(&bytes)
                .map_err(|_|OAuthError::Incompatible("local_request_invalid"))?)),
            None=>Ok(None)
        }
    }
    pub fn request_list(&self)->Result<Vec<String>>{
        let mut ids=Vec::new();
        for entry in fs::read_dir(&self.requests)?{
            let name=entry?.file_name();
            let Some(name)=name.to_str()else{continue};
            if let Some(id)=name.strip_suffix(".json"){
                if token_shape(id){ ids.push(id.to_owned()); }
            }
        }
        ids.sort();
        if ids.len()>256{return Err(OAuthError::PrivateState("request_directory_unbounded"));}
        Ok(ids)
    }
    pub fn enroll(&self,until:i64)->Result<()>{
        atomic_write(&self.enrollment,&serde_json::to_vec(&Enrollment{until})?,true)
    }
    pub fn approve(&self,request:&ApprovalRequest)->Result<()>{
        // Re-read the exact request. File names, deadline, audience and hash
        // are never accepted from an unauthenticated remote argument alone.
        let existing=self.request(&request.id)?
            .ok_or(OAuthError::Uncertain("approval_request_disappeared"))?;
        if existing.id!=request.id || existing.client_id!=request.client_id
            || existing.redirect!=request.redirect || existing.resource!=request.resource
            || existing.scope!=request.scope || existing.expires!=request.expires
            || existing.binding_hash!=request.binding_hash
            || existing.audience!=request.audience
            || existing.capability!=request.capability
        {
            return Err(OAuthError::Uncertain("approval_request_changed"));
        }
        atomic_write(
            &self.requests.join(format!("{}.approved",request.id)),
            &serde_json::to_vec(&Approval{
                binding_hash:request.binding_hash.clone(),
                expires:request.expires,
                audience:request.audience.clone(),
                capability:request.capability.clone(),
            })?,
            false
        )
    }
}

#[cfg(all(test, windows))]
#[path = "store_windows_tests.rs"]
mod windows_tests;
