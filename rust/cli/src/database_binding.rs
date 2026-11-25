//! The unified manifest pins and verifies the actual SQLite owner.
use crate::runtime::{RuntimeError,SharedCoreDatabase};
use agent_bridge_core::{CoreDatabase,physical_file_identity};
use serde_json::{json,Value};
use std::fs::{File,OpenOptions};
use std::path::{Path,PathBuf};
use std::sync::{Arc,Mutex};

pub(crate) struct DatabaseBinding {
    path:PathBuf,
    scope:Value,
    identity:String,
    file:File,
    #[cfg(windows)]
    _parent:Mutex<agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory>,
}
fn refuse()->RuntimeError {"DATABASE_AUTHORITY_CHANGED".into()}
impl DatabaseBinding {
    pub(crate) fn open(scope:&Value)->Result<Self,RuntimeError> {
        let path=PathBuf::from(scope["selected_path"].as_str().ok_or_else(refuse)?);
        if scope["present"]!=true || crate::gemini::scope_file(&path)?!=*scope {
            return Err(refuse());
        }
        #[cfg(windows)]
        let parent=agent_bridge_lifecycle::workspace_access::PinnedProjectDirectory::open(
            path.parent().ok_or_else(refuse)?)?;
        let file=open_pin(&path)?;
        let identity=physical_file_identity(&file)?;
        if crate::gemini::scope_file(&path)?!=*scope {return Err(refuse());}
        let bound=Self {path,scope:scope.clone(),identity,file,
            #[cfg(windows)] _parent:Mutex::new(parent)};
        bound.verify()?;
        Ok(bound)
    }
    pub(crate) fn authority(&self)->Value {
        json!({"selected_file":self.scope,"opened_file_identity":self.identity})
    }
    pub(crate) fn verify(&self)->Result<(),RuntimeError> {
        if crate::gemini::scope_file(&self.path)?!=self.scope
            || physical_file_identity(&open_pin(&self.path)?)?!=self.identity
            || physical_file_identity(&self.file)?!=self.identity {
            return Err(refuse());
        }
        Ok(())
    }
    pub(crate) fn acquire(&self,path:&Path,shared:Option<SharedCoreDatabase>)
        ->Result<SharedCoreDatabase,RuntimeError>
    {
        if std::fs::canonicalize(path)?!=std::fs::canonicalize(&self.path)? {
            return Err(refuse());
        }
        self.verify()?;
        let owner=match shared {
            Some(owner)=>owner,
            None=>Arc::new(Mutex::new(CoreDatabase::open_existing(path)?)),
        };
        {
            let mut core=owner.lock().map_err(|_|"CORE_UNAVAILABLE")?;
            if std::fs::canonicalize(core.path())?!=std::fs::canonicalize(&self.path)? {
                return Err(refuse());
            }
            core.bind_authority_file(&self.file)?;
        }
        self.verify()?;
        Ok(owner)
    }
}

fn open_pin(path:&Path)->Result<File,RuntimeError> {
    let mut options=OpenOptions::new(); options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0x00000001|0x00000002).custom_flags(0x00200000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file=options.open(path)?;
    let metadata=file.metadata()?;
    if !metadata.is_file() {return Err(refuse());}
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()&0x400!=0 {return Err(refuse());}
    }
    Ok(file)
}
