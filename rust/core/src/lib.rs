//! SQLite storage foundation for Agent Bridge.
//!
//! The SQLite schema is shared with the existing C# Core. No database or
//! migration is opened implicitly. Callers must supply an **offline, isolated**
//! absolute database path. A running Core's database is never an acceptable
//! migration target.
//!
//! `inspect_existing` uses SQLite's immutable read-only URI and rejects WAL,
//! SHM and rollback-journal sidecars. This deliberately cannot inspect a live
//! WAL database or recover uncheckpointed transactions.
//!
//! New initialization and upgrades are separate, explicit operations. Both
//! apply the original embedded C# SQL and record the same SHA-256 checksums.

mod legacy_owners;

use std::fs::{self, Metadata, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

pub const CURRENT_SCHEMA_VERSION: u32 = 7;
pub const MAX_INSPECTION_BYTES: u64 = 256 * 1024 * 1024;

const MIGRATIONS: [&str; 7] = [
    include_str!("../../../contracts/sqlite/001_initial.sql"),
    include_str!("../../../contracts/sqlite/002_execution.sql"),
    include_str!("../../../contracts/sqlite/003_collaboration.sql"),
    include_str!("../../../contracts/sqlite/004_scheduler.sql"),
    include_str!("../../../contracts/sqlite/005_legacy_import.sql"),
    include_str!("../../../contracts/sqlite/006_legacy_events.sql"),
    include_str!("../../../contracts/sqlite/007_legacy_mission_owners.sql"),
];

const MIGRATION_LEDGER: &str = "CREATE TABLE IF NOT EXISTS schema_migrations(\
    version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL, \
    compatibility_min INTEGER NOT NULL)";

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid Core database path: {0}")]
    InvalidPath(&'static str),
    #[error("Core history cannot be inspected safely: {0}")]
    UnsafeHistory(&'static str),
    #[error("incompatible Core schema: {0}")]
    IncompatibleSchema(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaStatus {
    /// Highest verified, contiguous schema migration in the existing database.
    pub version: u32,
    /// Number of first-party migrations still required to reach version 7.
    pub pending_migrations: u32,
}

/// A single caller-owned SQLite connection. No background worker, scheduler,
/// replica, or migration is started by constructing this value.
pub struct CoreDatabase {
    path: PathBuf,
    connection: Connection,
    // Optional unified authority pin; SQLite closes before this handle drops.
    _authority_file: Option<std::fs::File>,
}

impl CoreDatabase {
    /// Open a *fully migrated* offline database without creating or modifying
    /// its schema. An immutable read-only qualification happens first.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = qualified_path(path.as_ref())?;
        let status = inspect_existing(&path)?;
        if status.version != CURRENT_SCHEMA_VERSION {
            return Err(CoreError::IncompatibleSchema("migration required before opening"));
        }
        preflight_existing(&path)?;
        let connection = open_read_write(&path)?;
        if validate_schema(&connection)?.version != status.version {
            return Err(CoreError::IncompatibleSchema("schema changed during qualification"));
        }
        Ok(Self { path, connection, _authority_file: None })
    }

    /// Create a database only if the target path does NOT exist. The parent
    /// directory must already exist and must not traverse links/reparse points.
    /// WAL is enabled as in the C# Core, followed by all seven migrations in
    /// one transaction (including the guarded v7 legacy-owner backfill).
    pub fn initialize_new(path: impl AsRef<Path>) -> Result<Self> {
        let path = qualified_path(path.as_ref())?;
        reject_sidecars(&path)?;
        let mut creation = OpenOptions::new();
        creation.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            creation.mode(0o600);
        }
        // create_new is essential: never treat a pre-existing empty file as a
        // new database or use SQLite OPEN_CREATE to race into a real history.
        drop(creation.open(&path)?);

        let mut connection = open_read_write(&path)?;
        enable_wal(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(MIGRATION_LEDGER)?;
        apply_migrations(&tx, 0)?;
        assert_current(&tx)?;
        tx.commit()?;
        Ok(Self { path, connection, _authority_file: None })
    }

    /// Upgrade a *quiescent, offline* legacy Core database (verified schema
    /// 1 through 6) to 7. The initial check is strictly read-only; the ledger
    /// is checked again under the migration's SQLite write transaction.
    /// Already-current databases can be opened without migration.
    pub fn migrate_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = qualified_path(path.as_ref())?;
        let before = inspect_existing(&path)?;
        if before.version == CURRENT_SCHEMA_VERSION {
            return Self::open_existing(&path);
        }
        preflight_existing(&path)?;
        let mut connection = open_read_write(&path)?;
        enable_wal(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if validate_schema(&tx)?.version != before.version {
            return Err(CoreError::IncompatibleSchema("schema changed during qualification"));
        }
        apply_migrations(&tx, before.version)?;
        assert_current(&tx)?;
        tx.commit()?;
        Ok(Self { path, connection, _authority_file: None })
    }

    pub fn schema_version(&self) -> u32 {
        CURRENT_SCHEMA_VERSION
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Bind a caller-owned authority pin to the file actually opened by
    /// SQLite. Legacy opens never call this method or acquire this policy.
    pub fn bind_authority_file(&mut self, expected:&std::fs::File)->Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::{FromRawHandle,RawHandle};
            let mut handle:RawHandle=std::ptr::null_mut();
            // The bundled Windows VFS implements WIN32_GET_HANDLE (29), not
            // HAS_MOVED. The handle remains owned by the live connection.
            let status=unsafe {rusqlite::ffi::sqlite3_file_control(
                self.connection.handle(),c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
                (&mut handle as *mut RawHandle).cast(),
            )};
            if status!=rusqlite::ffi::SQLITE_OK || handle.is_null()
                || handle as isize == -1 {
                return Err(CoreError::UnsafeHistory("UNIFIED_DATABASE_HANDLE_IDENTITY_UNAVAILABLE"));
            }
            let sqlite_file=std::mem::ManuallyDrop::new(unsafe {
                std::fs::File::from_raw_handle(handle)
            });
            if physical_file_identity(&sqlite_file)?!=physical_file_identity(expected)? {
                return Err(CoreError::UnsafeHistory("DATABASE_AUTHORITY_CHANGED: opened SQLite file differs"));
            }
            self._authority_file=Some(expected.try_clone()?);
            Ok(())
        }
        #[cfg(not(windows))]
        {
            let _=expected;
            Err(CoreError::UnsafeHistory("UNIFIED_DATABASE_HANDLE_IDENTITY_UNAVAILABLE: unified VFS binding is qualified on Windows only"))
        }
    }

    /// Use the existing SQLite format directly; the caller controls its SQL,
    /// transaction scope and the lifetime of this one connection.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

/// Stable identity of an already-open file, never a reopened pathname.
pub fn physical_file_identity(file:&std::fs::File)->Result<String> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct FileIdInfo { volume_serial_number:u64, file_id:[u8;16] }
        #[link(name="kernel32")]
        extern "system" {
            fn GetFileInformationByHandleEx(handle:*mut std::ffi::c_void,
                class:i32,information:*mut std::ffi::c_void,size:u32)->i32;
        }
        let mut info=FileIdInfo {volume_serial_number:0,file_id:[0;16]};
        if unsafe {GetFileInformationByHandleEx(file.as_raw_handle(),18,
            (&mut info as *mut FileIdInfo).cast(),std::mem::size_of::<FileIdInfo>() as u32)}==0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let id=info.file_id.iter().map(|byte|format!("{byte:02x}")).collect::<String>();
        Ok(format!("windows:{:016x}:{id}",info.volume_serial_number))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata=file.metadata()?;
        Ok(format!("unix:{}:{}",metadata.dev(),metadata.ino()))
    }
    #[cfg(not(any(windows,unix)))]
    {
        let _=file;
        Err(CoreError::UnsafeHistory("physical file identity unavailable"))
    }
}

/// Verify an existing offline Core SQLite file without any write-capable open,
/// journal recovery, checkpoint, migration or schema creation. The returned
/// version may be 1..7; gaps, unknown versions and mismatched checksums fail.
pub fn inspect_existing(path: impl AsRef<Path>) -> Result<SchemaStatus> {
    let path = qualified_path(path.as_ref())?;
    preflight_existing(&path)?;
    let uri = immutable_uri(&path)?;
    let connection = Connection::open_with_flags(
        Path::new(&uri),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(3))?;
    connection.execute_batch("PRAGMA query_only=ON; PRAGMA foreign_keys=ON;")?;
    validate_schema(&connection)
}

fn open_read_write(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", 1_i64)?;
    Ok(connection)
}

fn enable_wal(connection: &Connection) -> Result<()> {
    let mode: String =
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(CoreError::UnsafeHistory("SQLite WAL mode could not be enabled"));
    }
    Ok(())
}

fn apply_migrations(tx: &Transaction<'_>, already_applied: u32) -> Result<()> {
    for (index, source) in MIGRATIONS.iter().enumerate().skip(already_applied as usize) {
        let version = (index + 1) as u32;
        let sql = migration_source(source);
        tx.execute_batch(sql)?;
        if version == 7 {
            // 007.sql alone is NOT the full v7 migration: the C# Core also
            // verifies ownership and redacts replay snapshots in this tx.
            legacy_owners::apply(tx)?;
        }
        tx.execute(
            "INSERT INTO schema_migrations(version,checksum,applied_at,compatibility_min) \
             VALUES(?1,?2,?3,1)",
            params![
                version,
                checksum(sql),
                Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, false)
            ],
        )?;
    }
    Ok(())
}

fn assert_current(connection: &Connection) -> Result<()> {
    if validate_schema(connection)?.version != CURRENT_SCHEMA_VERSION {
        return Err(CoreError::IncompatibleSchema("migration did not reach the current schema"));
    }
    let mut broken = connection.prepare("PRAGMA foreign_key_check")?;
    if broken.query([])?.next()?.is_some() {
        return Err(CoreError::IncompatibleSchema("foreign-key violations after migration"));
    }
    Ok(())
}

/// Read exactly the C# resource's logical UTF-8 text. StreamReader removes a
/// leading UTF-8 BOM; the SQL files themselves remain owned by Agent Bridge.
fn migration_source(source: &str) -> &str {
    source.strip_prefix('\u{feff}').unwrap_or(source)
}

fn checksum(sql: &str) -> String {
    format!("{:x}", Sha256::digest(sql.as_bytes()))
}

pub fn migration_checksum_matches(version: i64, recorded: &str) -> bool {
    if !(1..=i64::from(CURRENT_SCHEMA_VERSION)).contains(&version) {
        return false;
    }
    let original = migration_source(MIGRATIONS[(version - 1) as usize]);
    if recorded == checksum(original) {
        return true;
    }
    // The Unix C# bootstrap accepts only LF/CRLF variants of the same SQL;
    // a different statement or altered historical digest is never accepted.
    let lf = original.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    recorded == checksum(&lf) || recorded == checksum(&crlf)
}

fn validate_schema(connection: &Connection) -> Result<SchemaStatus> {
    let integrity: String =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(CoreError::UnsafeHistory("SQLite quick_check failed"));
    }

    if !table_exists(connection, "schema_migrations")? {
        return Err(CoreError::IncompatibleSchema("migration ledger is absent"));
    }
    let mut statement = connection.prepare(
        "SELECT version,checksum,compatibility_min FROM schema_migrations ORDER BY version",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0_usize;
    while let Some(row) = rows.next()? {
        let version: i64 = row.get(0)?;
        let recorded: String = row.get(1)?;
        let min_supported: i64 = row.get(2)?;
        if count >= MIGRATIONS.len()
            || version != (count + 1) as i64
            || min_supported != 1
            || !migration_checksum_matches(version, &recorded)
        {
            return Err(CoreError::IncompatibleSchema(
                "unknown, incomplete or modified migration ledger",
            ));
        }
        count += 1;
    }
    if count == 0 {
        return Err(CoreError::IncompatibleSchema("empty migration ledger"));
    }
    for table in ["missions", "operations", "agent_contexts"] {
        if !table_exists(connection, table)? {
            return Err(CoreError::IncompatibleSchema("required Core table is absent"));
        }
    }
    if count >= 3 && !table_exists(connection, "mission_memberships")? {
        return Err(CoreError::IncompatibleSchema("membership table is absent"));
    }
    Ok(SchemaStatus {
        version: count as u32,
        pending_migrations: CURRENT_SCHEMA_VERSION - count as u32,
    })
}

fn table_exists(connection: &Connection, name: &str) -> Result<bool> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}

fn qualified_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(CoreError::InvalidPath("a fully qualified file path is required"));
    }
    let raw = path.to_str().ok_or(CoreError::InvalidPath(
        "database path must be valid Unicode",
    ))?;
    if raw.starts_with("\\\\") || raw.starts_with("//") {
        return Err(CoreError::InvalidPath("remote or device paths are not supported"));
    }
    if path.components().any(|component| {
        matches!(component, Component::ParentDir | Component::CurDir)
    }) {
        return Err(CoreError::InvalidPath("dot and parent components are forbidden"));
    }
    // Reject ancestor symlinks and Windows junctions/reparse points before
    // opening the file. The caller must retain exclusive ownership of this
    // offline directory; these checks are not an inter-process lock.
    let parent = path
        .parent()
        .ok_or(CoreError::InvalidPath("missing parent directory"))?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        reject_reparse(&metadata)?;
        if !metadata.is_dir() {
            return Err(CoreError::InvalidPath("database parent is not a directory"));
        }
    }
    Ok(path.to_path_buf())
}

fn reject_reparse(metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(CoreError::UnsafeHistory("symbolic link in database path"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (metadata.file_attributes() & 0x400) != 0 {
            return Err(CoreError::UnsafeHistory("reparse point in database path"));
        }
    }
    Ok(())
}

fn preflight_existing(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    reject_reparse(&metadata)?;
    if !metadata.is_file() {
        return Err(CoreError::UnsafeHistory("not a regular SQLite file"));
    }
    if metadata.len() > MAX_INSPECTION_BYTES {
        return Err(CoreError::UnsafeHistory("history exceeds inspection size limit"));
    }
    reject_sidecars(path)
}

fn reject_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match fs::symlink_metadata(Path::new(&name)) {
            Ok(_) => return Err(CoreError::UnsafeHistory("SQLite sidecar present")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn immutable_uri(path: &Path) -> Result<String> {
    let native = path.to_str().ok_or(CoreError::InvalidPath(
        "database path must be valid Unicode",
    ))?;
    let forward = native.replace('\\', "/");
    let absolute = if cfg!(windows) {
        format!("/{forward}")
    } else {
        forward
    };
    let mut uri = String::from("file://");
    for byte in absolute.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~')
        {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}
